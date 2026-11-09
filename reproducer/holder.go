package main

import "database/sql"

type DBHolder struct{ Conn *sql.DB }
