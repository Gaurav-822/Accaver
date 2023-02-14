from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, select, Text

engine = create_engine('sqlite:///data.db')
meta = MetaData()

users = Table(
    'users', meta,
    Column('id', Integer, primary_key = True),
    Column('username', Text),
    Column('hash', Text),
    Column('cash', Integer),
    Column('spent', Integer),
    Column('gains', Integer),
    Column('income', Integer),
)

history_t = Table(
    'history', meta,
    Column('id', Integer),
    Column('descript', Text),
    Column('cashflow', Integer),
)
meta.create_all(engine)

conn = engine.connect()

select_stmt = history_t.select().where(history_t.c.id == 1)
result = conn.execute(select_stmt)
for row in result:
    print(row)


conn.close()
