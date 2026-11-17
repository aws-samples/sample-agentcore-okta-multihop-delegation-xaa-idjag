"""Before a rehearsal or the session: delete posted reviews and trace records."""
import os, sys
sys.path.insert(0, os.path.abspath("."))
import config as C
t = C.session().resource("dynamodb").Table(C.N["table"])
n = 0
for page in t.meta.client.get_paginator("scan").paginate(TableName=C.N["table"], ProjectionExpression="pk, sk"):
    with t.batch_writer() as w:
        for it in page["Items"]:
            w.delete_item(Key={"pk": it["pk"], "sk": it["sk"]}); n += 1
print(f"deleted {n} records")
