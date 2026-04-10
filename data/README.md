Place the MaxMind GeoLite2 City database file here as:

`GeoLite2-City.mmdb`

The backend reads the path from `GEOLITE2_DB_PATH` in `backend/.env`. By default this project expects:

`/home/raviteja/vscode/web/project/ddos/data/GeoLite2-City.mmdb`

Until that file exists, the backend will still run, but `latitude` and `longitude` will be `null`.
