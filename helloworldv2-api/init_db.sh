#!/usr/bin/env bash
sqlite3 test.db "CREATE TABLE IF NOT EXISTS flag (flag TEXT PRIMARY KEY);"
sqlite3 test.db "INSERT INTO FLAG VALUES ('reunion{i_Do_nOt_uNdErStAnD_JaVa}');"

sqlite3 test.db "CREATE TABLE IF NOT EXISTS quote (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, text TEXT NOT NULL);"

sqlite3 test.db "INSERT INTO quote (text) VALUES 
    ('i use arch btw UwU'),
    ('let''s w-wewwite e-evewything in rust'),
    ('\"0\" == [] is true');"