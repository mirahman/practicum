package main

import "net/http"

func crossHandler(db *DBHolder, w http.ResponseWriter, r *http.Request) {
name := r.URL.Query().Get("name")
runQuery(db.Conn, name)
}
