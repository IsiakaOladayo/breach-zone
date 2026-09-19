# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
import time
import datetime


class Client:
    """
    This is a time module
    """
    @staticmethod
    def unix():
        """
        Return the time stamp string,unit second

        @rtype: str
        @return: the time string, e.g 1491888244
        """
        return str(int(time.time()))

    @staticmethod
    def utc():
        """
        Return the UTC time string now

        @rtype: str
        @return: the time string, e.g 2020-11-24 09:44:45.426237 +0000 UTC
        """
        return str(datetime.datetime.utcnow())

    @staticmethod
    def sleep(t):
        """
        Suspends the current thread for the specified number of milliseconds.
        """
        time.sleep(t / 1000)

    @staticmethod
    def format(layout):
        """
        Format the UTC time now with the layout

        @type layout: str
        @param layout: the format of time, e.g yyyyMMdd hh:mm a EEEE

        @rtype: str
        @return: the time string, e.g 20060102 15:04 PM Monday
        """
        layout = layout.replace('yyyy', '%Y').replace('MM', '%m')\
            .replace('dd', '%d').replace('hh', '%H')\
            .replace('mm', '%M').replace('a', '%p')\
            .replace('EEEE', '%A')
        utc_now = datetime.datetime.utcnow().timetuple()
        return time.strftime(layout, utc_now)
