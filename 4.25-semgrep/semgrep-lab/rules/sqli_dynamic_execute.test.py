# sqli_dynamic_execute 规则配套测试（官方 annotation 约定）


def _bad_modulo():
    con = _placeholder_conn()
    cur = con.cursor()
    name = "x"
    # ruleid: sqli-exec-after-modulo-format
    q = "SELECT * FROM u WHERE n = '%s'" % name
    cur.execute(q)


# ok: sqli-exec-after-modulo-format
def _safe_parametrized():
    con = _placeholder_conn()
    cur = con.cursor()
    cur.execute("SELECT * FROM u WHERE n = ?", ("safe",))
    u = "u"
    cur.execute("SELECT * FROM u WHERE n = ?", (u,))


def _placeholder_conn():
    import sqlite3

    return sqlite3.connect(":memory:")
