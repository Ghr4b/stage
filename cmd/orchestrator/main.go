package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"tijeri/internal/adapters"
	"tijeri/internal/adapters/bundleraudit"
	"tijeri/internal/adapters/cargoaudit"
	"tijeri/internal/adapters/gitleaks"
	"tijeri/internal/adapters/govulncheck"
	"tijeri/internal/adapters/greenbone"
	"tijeri/internal/adapters/grype"
	"tijeri/internal/adapters/npmaudit"
	"tijeri/internal/adapters/nuclei"
	"tijeri/internal/adapters/osvscanner"
	"tijeri/internal/adapters/prowler"
	"tijeri/internal/adapters/syft"
	"tijeri/internal/adapters/tlsscan"
	"tijeri/internal/adapters/trivy"
	"tijeri/internal/adapters/uvaudit"
	"tijeri/internal/api"
	"tijeri/internal/defectdojo"
	"tijeri/internal/dependencytrack"
	"tijeri/internal/models"
	"tijeri/internal/msgbus"
	"tijeri/internal/normalize"
	"tijeri/internal/orchestrator"
	"tijeri/internal/risk"
	"tijeri/internal/siem"
	"tijeri/internal/store"
)

// Scanner is the full scanner interface that adapters implement.
type Scanner interface {
	Supports(asset models.Asset) bool
	Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error)
	Name() string
}

type scanJob struct {
	asset  models.Asset
	result chan error
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("Required environment variable %s is not set", name)
	}
	return v
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	fmt.Println("Tijeri Orchestrator starting...")
	if len(os.Getenv("TIJERI_API_TOKEN")) < 32 {
		log.Fatal("TIJERI_API_TOKEN must be configured with at least 32 characters")
	}
	if strings.EqualFold(os.Getenv("TLS_REQUIRED"), "true") &&
		(os.Getenv("TLS_CERT") == "" || os.Getenv("TLS_KEY") == "") {
		log.Fatal("TLS_REQUIRED is enabled but TLS_CERT or TLS_KEY is not configured")
	}
	oidcConfig, oidcEnabled, err := api.OIDCConfigFromEnv()
	if err != nil {
		log.Fatalf("Invalid OIDC configuration: %v", err)
	}
	scanners, scannerMap := initAdapters()
	if err := validateScannerRuntime(scannerMap); err != nil {
		log.Fatal(err)
	}
	if strings.EqualFold(os.Getenv("TLS_REQUIRED"), "true") && !oidcEnabled {
		log.Fatal("OIDC_ENABLED must be true when TLS_REQUIRED is enabled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var oidcAuthenticator *api.OIDCAuthenticator
	if oidcEnabled {
		oidcAuthenticator, err = api.NewOIDCAuthenticator(ctx, oidcConfig)
		if err != nil {
			log.Fatalf("Could not initialize OIDC: %v", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 1. Database
	dbURL := requireEnv("DATABASE_URL")
	sslmode := os.Getenv("PGSSLMODE")
	if sslmode != "" && !strings.Contains(dbURL, "sslmode=") {
		if strings.Contains(dbURL, "?") {
			dbURL += "&sslmode=" + sslmode
		} else {
			dbURL += "?sslmode=" + sslmode
		}
	}
	pgStore, err := store.NewPostgresStore(dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to Postgres: %v", err)
	}
	defer pgStore.Close()
	fmt.Println("  [DB] Connected to Postgres")

	if err := pgStore.Migrate(envOrDefault("MIGRATIONS_DIR", "migrations")); err != nil {
		log.Fatalf("Failed to apply migrations: %v", err)
	}
	fmt.Println("  [DB] Migrations applied")

	// 2. Message Bus (NATS)
	natsURL := requireEnv("NATS_URL")
	natsClient, err := msgbus.NewNATSClient(natsURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer natsClient.Close()
	fmt.Println("  [NATS] Connected")

	// 3. Object Store
	objStoreDir := envOrDefault("OBJECT_STORE_DIR", filepath.Join("data", "objectstore"))
	objStore, err := store.NewLocalObjectStore(objStoreDir)
	if err != nil {
		log.Fatalf("Failed to initialize object store: %v", err)
	}

	// 4. External Integrations
	dojoURL := envOrDefault("DEFECTDOJO_URL", "http://localhost:8081")
	dojoKey := requireEnv("DEFECTDOJO_API_KEY")
	dojoClient := defectdojo.NewClient(dojoURL, dojoKey)

	dtrackURL := envOrDefault("DTRACK_URL", "http://localhost:8082")
	var dtrackClient dependencytrack.Client
	if dtrackKey := os.Getenv("DTRACK_API_KEY"); dtrackKey != "" {
		dtrackClient = dependencytrack.NewClient(dtrackURL, dtrackKey)
	} else {
		log.Println("  [DTRACK] DTRACK_API_KEY not set; SBOM uploads to Dependency-Track will be skipped")
	}

	// 5. Router
	router := orchestrator.NewRouter(scanners)
	observer := orchestrator.NewObserver()
	scheduler := orchestrator.NewScheduler(nil)

	// 7. API Server
	apiServer := api.NewServerWithOIDC(pgStore, objStore, natsClient, oidcAuthenticator)
	addr := envOrDefault("API_ADDR", ":8080")
	certFile := os.Getenv("TLS_CERT")
	keyFile := os.Getenv("TLS_KEY")
	srv := &http.Server{
		Addr:              addr,
		Handler:           apiServer,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		var err error
		if certFile == "" || keyFile == "" {
			fmt.Printf("  [API] Starting on %s (HTTP development mode)\n", addr)
			err = srv.ListenAndServe()
		} else {
			fmt.Printf("  [API] Starting on %s (HTTPS)\n", addr)
			err = srv.ListenAndServeTLS(certFile, keyFile)
		}
		if err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	log.Println("[ML] Automatic retraining disabled until feedback labeling and model evaluation are production-safe")

	// 8. CDB Sync for Wazuh SIEM
	go startCDBSync(ctx, pgStore, apiServer)

	workerCount, err := scanWorkerCount()
	if err != nil {
		log.Fatalf("Invalid scan worker configuration: %v", err)
	}
	scanJobs := make(chan scanJob, workerCount)
	var scanWorkers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		scanWorkers.Add(1)
		go func() {
			defer scanWorkers.Done()
			for job := range scanJobs {
				job.result <- scanAsset(ctx, job.asset, router, scheduler, observer, pgStore, dojoClient, dtrackClient, scannerMap)
			}
		}()
	}
	var dispatchMu sync.Mutex
	var dispatchWG sync.WaitGroup
	acceptingScans := true
	queueScan := func(subject string, msg []byte) error {
		dispatchMu.Lock()
		if !acceptingScans {
			dispatchMu.Unlock()
			return errors.New("orchestrator is shutting down")
		}
		dispatchWG.Add(1)
		dispatchMu.Unlock()
		defer dispatchWG.Done()

		var asset models.Asset
		if err := json.Unmarshal(msg, &asset); err != nil {
			return fmt.Errorf("decode %s event: %w", subject, err)
		}
		if asset.AssetID == "" || asset.CanonicalName == "" {
			return fmt.Errorf("%s event is missing an asset ID or canonical name", subject)
		}
		job := scanJob{asset: asset, result: make(chan error, 1)}
		select {
		case scanJobs <- job:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-job.result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// 9. Subscribe to NATS for asset discovery events.
	if err := natsClient.Subscribe("tijeri.asset.discovered", func(msg []byte) error {
		return queueScan("tijeri.asset.discovered", msg)
	}); err != nil {
		log.Fatalf("Failed to create durable asset-discovery consumer: %v", err)
	}

	if err := natsClient.Subscribe("tijeri.scan.requested", func(msg []byte) error {
		return queueScan("tijeri.scan.requested", msg)
	}); err != nil {
		log.Fatalf("Failed to create durable scan-request consumer: %v", err)
	}

	fmt.Printf("Orchestrator is operational with %d scan workers. Waiting for asset events...\n", workerCount)

	var shutdownErr error
	select {
	case sig := <-sigCh:
		fmt.Printf("\nReceived %s; shutting down gracefully...\n", sig)
	case shutdownErr = <-serverErr:
		log.Printf("API server failed: %v", shutdownErr)
	}

	shutdownDeadline := time.Now().Add(40 * time.Second)
	shutdownCtx, shutdownCancel := context.WithDeadline(context.Background(), shutdownDeadline)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("API shutdown did not complete cleanly: %v", err)
	}
	shutdownCancel()
	dispatchMu.Lock()
	acceptingScans = false
	dispatchMu.Unlock()
	cancel()
	dispatchDone := make(chan struct{})
	go func() {
		dispatchWG.Wait()
		close(dispatchDone)
	}()
	select {
	case <-dispatchDone:
	case <-time.After(time.Until(shutdownDeadline)):
		log.Printf("Queue handlers did not stop before the shutdown deadline; closing NATS so unfinished jobs can be redelivered")
		natsClient.Close()
		return
	}
	natsClient.Close()
	close(scanJobs)
	workersDone := make(chan struct{})
	go func() {
		scanWorkers.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-time.After(time.Until(shutdownDeadline)):
		log.Printf("Scan workers did not stop before the shutdown deadline; unfinished JetStream jobs will be redelivered")
		return
	}
	if shutdownErr != nil {
		log.Fatalf("Orchestrator stopped after API server failure: %v", shutdownErr)
	}
	fmt.Println("Shutdown complete.")
}

// scanAsset runs the full scan pipeline for a single asset.
func scanAsset(
	ctx context.Context,
	asset models.Asset,
	router *orchestrator.Router,
	scheduler *orchestrator.Scheduler,
	observer *orchestrator.Observer,
	db store.Store,
	dojo *defectdojo.Client,
	dtrack dependencytrack.Client,
	scannerMap map[string]Scanner,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	job := orchestrator.ScanJob{
		Asset:    asset,
		Trigger:  "push",
		QueuedAt: time.Now(),
	}

	if !scheduler.ShouldRunNow(job) {
		fmt.Printf("[Pipeline] Deferring scan for %s (outside maintenance window)\n", asset.CanonicalName)
		return nil
	}

	fmt.Printf("[Pipeline] Scanning asset %s (type: %s)...\n", asset.CanonicalName, asset.Type)

	if err := db.SaveAsset(ctx, asset); err != nil {
		fmt.Printf("[Pipeline] Failed to save asset: %v\n", err)
		return fmt.Errorf("save asset: %w", err)
	}

	adapterNames := router.Route(ctx, asset)
	if len(adapterNames) == 0 {
		fmt.Printf("[Pipeline] No adapters match asset %s\n", asset.CanonicalName)
		return nil
	}

	fmt.Printf("[Pipeline] Matched adapters: %v\n", adapterNames)

	var allFindings []models.Finding
	var scanFailures []string
	var attemptedScans int
	var successfulScans int
	for _, name := range adapterNames {
		scanner, ok := scannerMap[name]
		if !ok {
			attemptedScans++
			scanFailures = append(scanFailures, name+" (not initialized)")
			continue
		}

		attemptedScans++
		start := time.Now()
		batch, err := scanner.Scan(ctx, asset)
		duration := time.Since(start).Milliseconds()

		if err != nil {
			observer.RecordJobResult(orchestrator.JobResult{
				JobID:         fmt.Sprintf("job-%s-%d", asset.AssetID, time.Now().UnixNano()),
				AssetID:       asset.AssetID,
				Adapter:       name,
				Status:        orchestrator.JobStatusFailed,
				FailureReason: err.Error(),
				DurationMs:    duration,
				Timestamp:     time.Now(),
			})
			fmt.Printf("[Pipeline]   %s failed: %v\n", name, err)
			scanFailures = append(scanFailures, name)
			continue
		}
		successfulScans++

		observer.RecordJobResult(orchestrator.JobResult{
			JobID:         fmt.Sprintf("job-%s-%d", asset.AssetID, time.Now().UnixNano()),
			AssetID:       asset.AssetID,
			Adapter:       name,
			Status:        orchestrator.JobStatusSuccess,
			FindingsCount: len(batch.Findings),
			DurationMs:    duration,
			Timestamp:     time.Now(),
		})
		fmt.Printf("[Pipeline]   %s found %d issues (%dms)\n", name, len(batch.Findings), duration)
		allFindings = append(allFindings, batch.Findings...)
	}
	if attemptedScans == 0 {
		return fmt.Errorf("no initialized scanners matched routed adapters %v", adapterNames)
	}
	if successfulScans == 0 {
		return fmt.Errorf("all %d scanners failed for asset %s: %s", attemptedScans, asset.AssetID, strings.Join(scanFailures, ", "))
	}

	deduped := normalize.DedupFindings(allFindings)
	fmt.Printf("[Pipeline] After dedup: %d unique findings\n", len(deduped))

	persistenceFailed := false
	for i := range deduped {
		f := &deduped[i]
		if f.AssetID == "" {
			f.AssetID = asset.AssetID
		}
		f.DedupHash = normalize.GenerateDedupHash(*f)

		exposure := true
		kev := f.KEVListed
		automatable := true
		techImpact := f.CVSS != nil && f.CVSS.Score >= 7.0

		baseDeadline := risk.CalculateBOD2604Deadline(&exposure, kev, &automatable, techImpact)
		finalDeadline, _ := risk.ApplyCriticalityOverride(baseDeadline, asset.CriticalityTier)
		_ = finalDeadline

		if err := db.SaveFinding(ctx, *f); err != nil {
			fmt.Printf("[Pipeline]   Failed to save finding %s: %v\n", f.VulnerabilityID, err)
			persistenceFailed = true
		}
	}
	if persistenceFailed {
		fmt.Printf("[Pipeline] Aborting downstream sync for %s because finding persistence failed\n", asset.CanonicalName)
		return errors.New("persist one or more findings")
	}
	if len(scanFailures) > 0 {
		return fmt.Errorf("partial scan for asset %s: %d of %d scanners failed (%s)", asset.AssetID, len(scanFailures), attemptedScans, strings.Join(scanFailures, ", "))
	}

	if _, err := dojo.EnsureAssetProduct(ctx, asset); err != nil {
		fmt.Printf("[Pipeline]   DefectDojo product sync failed for %s: %v\n", asset.CanonicalName, err)
		return fmt.Errorf("ensure DefectDojo product: %w", err)
	}
	fmt.Printf("[Pipeline]   DefectDojo product ensured for %s\n", asset.CanonicalName)

	if len(deduped) == 0 {
		fmt.Printf("[Pipeline] No findings for %s\n", asset.CanonicalName)
		return nil
	}

	batch := models.FindingsBatch{Findings: deduped}
	for _, adapterName := range adapterNames {
		if err := dojo.PushBatch(ctx, asset, adapterName, batch); err != nil {
			fmt.Printf("[Pipeline]   DefectDojo push failed: %v\n", err)
			return fmt.Errorf("push findings to DefectDojo: %w", err)
		} else {
			fmt.Printf("[Pipeline]   Pushed %d findings to DefectDojo\n", len(deduped))
		}
		break
	}

	if asset.Type == "container" && dtrack != nil {
		syftAdapter := &syft.Adapter{}
		if syftAdapter.Supports(asset) {
			sbomBatch, err := syftAdapter.Scan(ctx, asset)
			if err != nil {
				return fmt.Errorf("scan container SBOM: %w", err)
			}
			if len(sbomBatch.Findings) > 0 {
				sbomJSON, _ := json.Marshal(map[string]interface{}{
					"bomFormat":    "CycloneDX",
					"specVersion":  "1.6",
					"serialNumber": asset.AssetID,
					"components":   sbomBatch.Findings,
				})
				if err := dtrack.UploadSBOM(ctx, asset.CanonicalName, "1.0", sbomJSON); err != nil {
					fmt.Printf("[Pipeline]   Dependency-Track SBOM push failed: %v\n", err)
					return fmt.Errorf("upload SBOM to Dependency-Track: %w", err)
				} else {
					fmt.Printf("[Pipeline]   Pushed SBOM to Dependency-Track\n")
				}
			}
		}
	}

	fmt.Printf("[Pipeline] Complete for %s: %d findings saved\n", asset.CanonicalName, len(deduped))
	return nil
}

func startCDBSync(ctx context.Context, db store.Store, apiServer *api.Server) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Create CDB directory if it doesn't exist
	if err := os.MkdirAll("/shared/cdb", 0755); err != nil {
		fmt.Printf("[CDB] Warning: Failed to create /shared/cdb directory: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hosts, err := db.GetVulnerableHosts(ctx)
			if err != nil {
				fmt.Printf("[CDB] Failed to query vulnerable hosts: %v\n", err)
				continue
			}
			apiServer.UpdateCDBList(hosts)
			cdbContent := siem.GenerateCDBList(hosts)

			// Write to shared volume for Wazuh
			err = os.WriteFile("/shared/cdb/vulnerable_ips", []byte(cdbContent), 0644)
			if err != nil {
				fmt.Printf("[CDB] Failed to write vulnerable_ips: %v\n", err)
			} else {
				fmt.Printf("[CDB] Updated CDB list: %d vulnerable hosts, %d bytes\n", len(hosts), len(cdbContent))
			}
		}
	}
}

// adapterWrapper bridges the concrete adapter types to the orchestrator.ScannerAdapter interface.
type adapterWrapper struct {
	name  string
	inner Scanner
}

func (w *adapterWrapper) Name() string                     { return w.name }
func (w *adapterWrapper) Supports(asset models.Asset) bool { return w.inner.Supports(asset) }

func initAdapters() ([]orchestrator.ScannerAdapter, map[string]Scanner) {
	scannerMap := map[string]Scanner{
		"trivy":         &trivy.Adapter{Config: trivy.Config{VEXEnabled: true}},
		"grype":         &grype.Adapter{},
		"syft":          &syft.Adapter{},
		"gitleaks":      gitleaks.NewAdapter(gitleaks.Config{}),
		"npm audit":     npmaudit.NewAdapter(npmaudit.Config{}),
		"govulncheck":   govulncheck.NewAdapter(govulncheck.Config{}),
		"cargo audit":   cargoaudit.NewAdapter(cargoaudit.Config{}),
		"bundler-audit": bundleraudit.NewAdapter(bundleraudit.Config{}),
		"uv audit":      uvaudit.NewAdapter(uvaudit.Config{}),
		"osv-scanner":   osvscanner.NewAdapter(osvscanner.Config{}),
		"nuclei":        nuclei.NewAdapter(nuclei.Config{}),
		"tlsscan":       tlsscan.NewAdapter(tlsscan.Config{}),
		"prowler":       prowler.NewAdapter(),
	}

	// Greenbone requires an OpenVAS/GVM daemon (gvm-cli/omp + local socket);
	// it's only registered when a GVM socket path is provisioned.
	if envOrDefault("GVM_SOCKET", "") != "" {
		scannerMap["greenbone"] = greenbone.NewAdapter(greenbone.Config{})
	}

	var routerAdapters []orchestrator.ScannerAdapter
	for name, scanner := range scannerMap {
		routerAdapters = append(routerAdapters, &adapterWrapper{name: name, inner: scanner})
		fmt.Printf("  [Adapter] Registered: %s\n", name)
	}

	return routerAdapters, scannerMap
}

func validateScannerRuntime(scannerMap map[string]Scanner) error {
	scannerNames := make([]string, 0, len(scannerMap))
	for name := range scannerMap {
		scannerNames = append(scannerNames, name)
	}
	capabilities := adapters.InspectScannerCapabilities(scannerNames)
	var missing []string
	available := 0
	for _, capability := range capabilities {
		if capability.Available {
			available++
			continue
		}
		missing = append(missing, fmt.Sprintf("%s (%s)", capability.Scanner, strings.Join(capability.Missing, " or ")))
		log.Printf("[Scanner] %s unavailable; missing executable(s): %s", capability.Scanner, strings.Join(capability.Missing, ", "))
	}
	log.Printf("[Scanner] Runtime capability check: %d/%d adapters available", available, len(capabilities))
	if len(missing) > 0 && strings.EqualFold(os.Getenv("SCANNER_PREFLIGHT_REQUIRED"), "true") {
		return fmt.Errorf("required scanner executables are missing: %s", strings.Join(missing, "; "))
	}
	return nil
}
