package main

import "database/sql"

func runQuery(db *sql.DB, name string) {
main.go db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
