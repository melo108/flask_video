# _*_ coding:utf-8 _*_
__author__ = 'jimmy'
__date__ = '2018/2/13 10:53'

from flask import Blueprint

admin = Blueprint('admin',__name__)
import app.admin.views
