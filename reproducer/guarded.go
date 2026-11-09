package main

import "net/http"

func guardedHandler(db *DBHolder, w http.ResponseWriter, r *http.Request) {
name := clean(r.URL.Query().Get("name"))
runQuery(db.Conn, name)
}
