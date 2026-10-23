\getenv tijeri_database_password TIJERI_DATABASE_PASSWORD
\getenv dd_database_password DD_DATABASE_PASSWORD
\getenv dtrack_database_password DTRACK_DATABASE_PASSWORD

CREATE ROLE tijeri_app LOGIN PASSWORD :'tijeri_database_password';
ALTER DATABASE tijeri OWNER TO tijeri_app;
GRANT ALL ON DATABASE tijeri TO tijeri_app;
CREATE ROLE defectdojo LOGIN PASSWORD :'dd_database_password';
CREATE DATABASE defectdojo OWNER defectdojo;
CREATE ROLE dtrack LOGIN PASSWORD :'dtrack_database_password';
CREATE DATABASE dependencytrack OWNER dtrack;
