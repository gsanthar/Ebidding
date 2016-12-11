

SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{username}:{password}@{hostname}/{databasename}".format(
    username="gsanthar",
    password="ganesh123",
    hostname="flaskbid.c67d5zvfo5mn.us-west-2.rds.amazonaws.com:3306",
    databasename="biddb",
)


SQLALCHEMY_POOL_RECYCLE = 3600

