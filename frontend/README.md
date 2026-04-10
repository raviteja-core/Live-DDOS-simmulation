# Frontend MVP

This is the frontend MVP for Iteration 4 and Iteration 5 of the DDoS threat globe, set up as a Vite app.

## Run locally

1. Start the backend on `http://127.0.0.1:8000`
2. Install frontend dependencies:

```bash
cd /home/raviteja/vscode/web/project/ddos/frontend
npm install
```

3. Start the frontend:

```bash
cd /home/raviteja/vscode/web/project/ddos/frontend
npm run dev -- --host 0.0.0.0
```

4. Open:

`http://127.0.0.1:4173`

If your backend runs somewhere else, open:

`http://127.0.0.1:4173/?api=http://127.0.0.1:8000`

## Notes

- The app fetches `GET /threats?limit=100`
- Only threats with `latitude` and `longitude` are rendered
- The globe shows mapped threat points plus simulated attack arcs toward protected network hubs
- If GeoLite2 is not configured on the backend yet, the globe will load but show `0` visible points
- You can also set `VITE_API_BASE_URL` in a frontend `.env` file if you want a default API base URL
