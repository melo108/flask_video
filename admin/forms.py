# _*_ coding:utf-8 _*_
__author__ = 'jimmy'
__date__ = '2018/2/13 11:03'

from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SelectField,SubmitField,FileField,TextAreaField,TextField,SelectMultipleField
from wtforms.validators import DataRequired,ValidationError,EqualTo

from app.models import Admin,Tag,Auth,Role

tags = Tag.query.all()

class LoginForm(FlaskForm):
    """
    管理员登录的验证表单
    """
    account = StringField(
        label='账号',
        validators=[DataRequired('请输入账号！')],
        description='账号',
        render_kw={
            'class':'form-control',
            'placeholder':'请输入账号',
            # 'required':'required'  # 会在 前端浏览器 做验证
        }
    )

    pwd = PasswordField(
        label='密码',
        validators= [
            DataRequired('请输入密码！')
        ],
        description='密码',
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入密码',
            # 'required': 'required'  #  会在前端浏览器做验证
        }
    )

    submit = SubmitField(
        '登录',
        render_kw={
            'class':'btn btn-primary btn-block btn-flat'
        }
    )


    def validate_account(self,field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError('账号不存在')


class TagForm(FlaskForm):
    name = StringField(
        label='名称',
        validators= [
            DataRequired('请输入标签'),
        ],
        description= '标签名',
        render_kw={
            'type': "text",
            'class':"form-control",
            'placeholder':"请输入标签名称！"
        }
    )

    submit = SubmitField(
        '添加',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )

    # def validate_name(self,field):
    #     name = field.data
    #     tag = Tag.query.filter_by(name=name).count()
    #     if tag == 1:
    #         raise ValidationError('标签已经存在')


class MovieForm(FlaskForm):

    title = StringField(
        label='片名',
        validators=[DataRequired('片名！')],
        description='片名',
        render_kw={
            'type': "text",
            'class': "form-control",
            'placeholder': "请输入片名！"
        })
    url = FileField(
        label='url',
        validators=[DataRequired('url！')],
        description='url',
    )
    info = TextAreaField(
        label='简介',
        validators=[DataRequired('简介！')],
        description='简介',
        render_kw={
            'class': "form-control",
            'rows': 10
        })

    logo = FileField(
        label='封面',
        validators=[DataRequired('封面！')],
        description='封面',
    )

    star = SelectField(
        label = '星级',
        validators=[DataRequired('选择星级！')],
        description='星级',
        render_kw={
            'class': "form-control",
        },
        coerce= int,
        choices=[
            (1,'1星'),
            (2,'2星'),
            (3,'3星'),
            (4,'4星'),
            (5,'5星'),

        ]
    )
    tag_id = SelectField(
        label = '标签',
        validators=[DataRequired('选择标签！')],
        description='标签',
        render_kw={
            'class': "form-control",
        },
        coerce= int,
        choices=[
            (v.id, v.name) for v in tags]
    )


    area = StringField(
        label='上映地区',
        validators=[DataRequired('上映地区')],
        description='上映地区',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入地区名称！"
        })
    length = StringField(
        label='片长',
        validators=[DataRequired('片长！')],
        description='片长',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入片长！"
        })

    release_time = StringField(
        label='上映时间',
        validators=[DataRequired('上映时间！')],
        description='上映时间',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入上映时间！",
            'id':'input_release_time'
        })

    submit = SubmitField(
        '添加',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )


class PreviewForm(FlaskForm):
    title = StringField(
        label='预告名称',
        validators=[DataRequired('预告名称！')],
        description='预告名称',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入预告名名！"
        })
    logo = FileField(
        label='封面',
        validators=[DataRequired('请上传封面！')],
        description='封面',
    )

    submit = SubmitField(
        '提交',
        render_kw={
            'class':'btn btn-primary btn-block btn-flat'
        }
    )


class PWDForm(FlaskForm):
    old_pwd = PasswordField(
        label = '旧密码',
        validators = [
            DataRequired('请输入旧密码')
        ],
        description='旧密码',
        render_kw={
            'class':'form-control',
            'placeholder':'请输入旧密码'
        }
    )
    new_pwd = PasswordField(
        label = '新密码',
        validators = [
            DataRequired('请输入新密码')
        ],
        description='新密码',
        render_kw={
            'class':'form-control',
            'placeholder':'请输入新密码'
        }
    )

    submit = SubmitField(
        '提交',
        render_kw={
            'class':'btn btn-primary btn-block btn-flat'
        }
    )

    def validate_old_pwd(self,field):
        from flask import session
        pwd = self.data['old_pwd']
        name = session['admin']
        admin = Admin.query.filter_by(
            name=name
        ).first()
        if not admin.check_pwd(pwd):
            raise ValidationError('旧密码错误！')


class AuthForm(FlaskForm):
    name = StringField(
        label='权限名称',
        validators=[
            DataRequired('请输入权限名称'),
        ],
        description='权限名称',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入权限名称！"
        }
    )
    url = StringField(
        label='权限url',
        validators=[
            DataRequired('请输入权限url'),
        ],
        description='权限url',
        render_kw={
            'class': "form-control",
            'placeholder': "请输入权限url！"
        }
    )
    submit = SubmitField(
        '提交',
        render_kw={
            'class':'btn btn-primary btn-block btn-flat'
        }
    )


class RoleForm(FlaskForm):

    name = StringField(
        label='角色名称',
        validators=[
            DataRequired('请输入角色')
        ],
        description='角色名称',
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入角色'
        }
    )

    auths = SelectMultipleField(
        label='权限列表',
        validators=[
            DataRequired('请选择权限')
        ],
        coerce=int,
        choices=[(v.id,v.name) for v in Auth.query.all()],
        description='权限列表',
        render_kw={
            'class': 'form-control',
        }
    )

    submit = SubmitField(
        '提交',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )


class AdminForm(FlaskForm):
    name = StringField(
        label='管理员名称',
        validators=[DataRequired('输入管理员名称'),],
        render_kw={
            'class':'form-control',
            'placeholder': "请输入管理员！"
        },
        description='管理员名称',
    )
    pwd = PasswordField(
        label='输入密码',
        validators=[DataRequired('输入密码'),
                    # EqualTo('re_pwd',message='密码不一致！')
                    ],
        render_kw={
            'class':'form-control',
            'placeholder': "请输入密码！"
        },
        description='输入密码',
    )
    re_pwd = PasswordField(
        label='重复密码',
        validators=[DataRequired('重复密码'),],
        render_kw={
            'class':'form-control',
            'placeholder': "请重复密码！"
        },
        description='请重复密码',
    )
    role_id = SelectField(
        label='选择角色',
        validators=[DataRequired('选择角色'),
                    ],
        coerce=int,
        choices=[(v.id,v.name) for v in Role.query.all()],
        render_kw={
            'class':'form-control',
        },
    )
    submit = SubmitField(
        '提交',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )

    def validate_re_pwd(self,field):
        if  self.data['pwd'] != field.data:
            raise ValidationError('两次密码不一致')
