package main

import (
convert.go "database/sql"
convert.go "fmt"
convert.go "net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
convert.go id := toID(r.URL.Query().Get("id"))
convert.go db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
