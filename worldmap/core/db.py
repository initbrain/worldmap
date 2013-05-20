# -*- coding: utf-8 -*-

from time import mktime, localtime, sleep

from worldmap.core.constants import WORLDMAP_PATH

from peewee import SqliteDatabase, Model, RawQuery
from peewee import CharField, IntegerField, FloatField, BooleanField
from peewee import ForeignKeyField


class IPdb(SqliteDatabase):
    """
    SQLite database object.
    """
    def connect(self):
        super(IPdb, self).connect()
        pragma = RawQuery(BaseModel, "PRAGMA foreign_keys = ON;")
        self.execute(pragma)


class BaseModel(Model):
    """
    Basic database model, uses RSSdb as the database object.
    """
    class Meta:
        database = IPdb("%s/core/knowledge.db" % WORLDMAP_PATH, check_same_thread=False)


class IP(BaseModel):
    """
    IP model.
    """
    op = CharField(max_length=256, null=True)
    lon = FloatField(null=True)
    lat = FloatField(null=True)
    cid = CharField(max_length=256, null=True)
    mcc = CharField(max_length=256, null=True)
    mnc = CharField(max_length=256, null=True)
    lac = CharField(max_length=256, null=True)
    date = IntegerField(default=int(mktime(localtime())))
    mapped = BooleanField(default=False)

    def __str__(self):
        return "<IP '%s (%f:%f)'>" % (self.op, self.lon, self.lat)

    # def del_emails(self):
    #     deleted = 0
    #     for email in self.emails:
    #         deleted += email.delete_instance()
    #     return deleted

    @classmethod
    def get_already_mapped(cls):
        try:
            query = cls.select().where(
                cls.mapped == True
            )
        except IP.DoesNotExist as err:
            return False #sleep(3)
        else:
            return query

    @classmethod
    def get_non_mapped(cls):
        while True:
            try:
                query = cls.select().where(
                    cls.mapped == False
                )
                query.get()
            except IP.DoesNotExist as err:
                sleep(3)
            else:
                return query

    @classmethod
    def if_already_mapped(cls, lon, lat):
        while True:
            try:
                query = cls.select().where(
                    cls.lon == lon,
                    cls.lat == lat,
                    cls.mapped == True
                ).get()
            except IP.DoesNotExist as err:
                return False
            else:
                return query

    # @classmethod
    # def get_by_id(cls, id):
    #     return cls.select().where(
    #         cls.id == id
    #     ).get()
    #
    # @classmethod
    # def del_by_url(cls, url):
    #     feed = cls.get_by_url(url)
    #     del_emails = feed.emails.count()
    #     del_feeds = feed.delete_instance(recursive=True)
    #     return del_feeds, del_emails
    #
    # @classmethod
    # def del_by_id(cls, id):
    #     feed = cls.get_by_id(id)
    #     del_emails = feed.emails.count()
    #     del_feeds = feed.delete_instance(recursive=True)
    #     return del_feeds, del_emails

IP.create_table(fail_silently=True)