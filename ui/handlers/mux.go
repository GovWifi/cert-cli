package handlers

import (
	"io/fs"
	"net/http"
)

// New returns the UI HTTP handler. staticRoot should contain index.html and
// other assets (style.css, app.js, …) at its root.
func New(staticRoot fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))
	mux.HandleFunc("GET /{$}", serveIndex(staticRoot))
	mux.HandleFunc("POST /api/gen/root", handleGenRoot)
	mux.HandleFunc("POST /api/gen/inter", handleGenInter)
	mux.HandleFunc("POST /api/gen/all", handleGenAll)
	mux.HandleFunc("POST /api/validate", handleValidate)
	mux.HandleFunc("POST /api/save", handleSave)
	return mux
}

func serveIndex(staticRoot fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(staticRoot, "index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}
}
