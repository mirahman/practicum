package main

import (
"database/sql"
"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
name := r.URL.Query().Get("name")
db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
