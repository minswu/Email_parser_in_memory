#-*- coding: utf-8 -*-

import sqlite3

def create_DB(db_path):
    global dbpath
    dbpath = db_path

    # if not os.path.exists(dbpath):
    #     os.makedirs(dbpath)
    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS email_info(Service TEXT, Subject TEXT, Body TEXT, SentDate TIMESTAMP NOT NULL, Sender TEXT, Recipient TEXT, CC TEXT, BCC TEXT, Description TEXT)")

    conn.commit()

def email_db(result):
    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()
    cur.execute("INSERT INTO email_info VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (result['Service'], result['Subject'], result['Body'], str(result['SentDate']), result['Sender'], result['Recipient'], result['CC'], result['BCC'], result['Description']))
    conn.commit()