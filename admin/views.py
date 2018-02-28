# _*_ coding:utf-8 _*_
__author__ = 'jimmy'
__date__ = '2018/2/13 11:04'

from . import admin
from flask import render_template,redirect,url_for,flash,session,request,abort
from functools import wraps
from werkzeug.utils import secure_filename

import os
import uuid
import datetime

from .forms import AdminForm,LoginForm,TagForm,MovieForm,PreviewForm,PWDForm,AuthForm,RoleForm
from app.models import User,Admin,Tag,Movie,Preview,Comment,MovieCol,Auth,Role
from app import db,app

# ==========================函数===========================

# 修改 文件名函数 ---- 时间 + 唯一字符串 + 文件后缀
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S")+str(uuid.uuid4().hex)+fileinfo[-1]
    return filename

#   登录装饰器
def admin_login_req(f):
    @wraps(f)
    def decorator(*args,**kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin.login',next=request.url))
        return f(*args,**kwargs)
    return decorator

# 权限控制装饰器

def admin_auth(f):
    @wraps(f)
    def decorator(*args,**kwargs):
        admin = Admin.query.filter_by(name = session['admin']).first()
        # admin = Admin.query.join(Role).filter(Role.id == Admin.role_id,Admin.id == session['admin_id'] ).first()
        auths = admin.get_role().auths
        # auths = admin.role.auths
        auths = list(map(lambda i:int(i),auths.split(';')))
        auth_url_list = Auth.query.all()
        urls = [ auth_url.url for auth_url in auth_url_list for auth in auths if auth == auth_url.id]
        if str(request.path) not in urls:
            abort(404)
        return f(*args,**kwargs)
    return decorator




# ====================== login  logout ======================
@admin.route('/')
@admin_login_req
@admin_auth
def index():
    return render_template('admin/index.html')

@admin.route('/login/',methods=['GET','POST'])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        data = loginform.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误！')
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        return redirect(request.args.get('next') or url_for('admin.index'))


    return render_template('admin/login.html',loginform=loginform)

@admin.route('/logout/')
@admin_login_req
def logout():
    session.pop('admin','')
    return redirect(url_for('admin.login'))



# ================= 修改密码 =================

@admin.route('/pwd/',methods=['GET','POST'])
@admin_login_req
def pwd():
    pwd_form = PWDForm()
    if pwd_form.validate_on_submit():
        data = pwd_form.data
        new_pwd = data['new_pwd']
        name = session['admin']
        admin = Admin.query.filter_by(
            name=name
        ).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(new_pwd)
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功,请重新登录！','ok')
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html',pwd_form=pwd_form)


# ================== 标签 ==========================

@admin.route('/tag/add/',methods=['GET','POST'])
@admin_login_req
def tag_add():
    tagform = TagForm()
    if tagform.validate_on_submit():
        data = tagform.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash('标签已经存在','err')
            return redirect(url_for('admin.tag_add'))

        tag = Tag(
            name=data['name']
        )

        db.session.add(tag)
        db.session.commit()

        flash('添加成功','ok')  #  过滤flash消息
        return redirect(url_for('admin.tag_add'))

    return render_template('admin/tag-add.html',tagform=tagform)
# 标签 列表
@admin.route('/tag/list/<int:page>/',methods=['GET'])
@admin_login_req
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page,per_page=5)
    return render_template('admin/tag-list.html',page_data=page_data)
# 标签删除
@admin.route('/tag/del/<int:id>/',methods=['GET'])
@admin_login_req
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('删除标签成功','ok')
    return redirect(url_for('admin.tag_list',page=1))
# 标签 修改
@admin.route('/tag/edit/<int:id>/',methods=['GET','POST'])
@admin_login_req
def tag_edit(id):
    tagform = TagForm()
    tag = Tag.query.get_or_404(id)
    if tagform.validate_on_submit():
        data = tagform.data
        if data['name'] == tag.name:
            flash('没有修改','ok')
            return redirect(url_for('admin.tag_list',page=1))

        elif Tag.query.filter_by(name=data['name']).count() == 1:
            flash('标签已经存在','err')
            return redirect(url_for('admin.tag_list',page=1))

        else:
            tag.name = data['name']
            db.session.add(tag)
            db.session.commit()
            flash('修改标签成功','ok')
            return redirect(url_for('admin.tag_list',page=1))
    return render_template('admin/tag-add.html',tag=tag,tagform=tagform)




# ====================电影=============================

@admin.route('/movie/add/',methods=['GET','POST'])
@admin_login_req
def movie_add():
    movieform = MovieForm()
    if movieform.validate_on_submit():
        data = movieform.data
        file_url = secure_filename(movieform.url.data.filename)
        file_logo = secure_filename(movieform.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'],'rw')

        url_ = change_filename(file_url)
        logo_ = change_filename(file_logo)

        movieform.url.data.save(app.config['UP_DIR']+url_)
        movieform.logo.data.save(app.config['UP_DIR']+logo_)

        movie = Movie(
            title = data['title'],
            url = url_,
            info = data['info'],
            logo = logo_,
            star = int(data['star']),
            play_num = 0,
            comment_num = 0,
            tag_id = int(data['tag_id']),
            area = data['area'],
            release_time = data['release_time'],
            length = data['length']
        )

        db.session.add(movie)
        db.session.commit()
        flash('添加电影成功','ok')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie-add.html',movieform=movieform)
# 电影列表
@admin.route('/movie/list/<int:page>/',methods=['GET','POST'])
@admin_login_req
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id==Movie.tag_id).order_by(
        Movie.addtime.desc()
    ).paginate(page=page,per_page=5)
    return render_template('admin/movie-list.html',page_data=page_data)
# 删除电影操作
@admin.route('/movie/del/<int:id>/',methods=['GET'])
@admin_login_req
def movie_del(id=None):
    movie = Movie.query.filter_by(id=int(id)).first_or_404()
    db.session.delete(movie)
    db.session.commit()
    flash('电影删除成功！','ok')
    return redirect(url_for('admin.movie_list',page=1))
# 编辑电影操作
@admin.route('/movie/edit/<int:id>/',methods=['GET','POST'])
@admin_login_req
def movie_edit(id=None):
    movieform = MovieForm()
    movie = Movie.query.get_or_404(id)
    # 编辑的时候 url 封面资源可以不传 ，设置 validators=[]
    movieform.url.validators=[]
    movieform.logo.validators=[]

    if request.method == 'GET':
        movieform.star.data = movie.star
        movieform.tag_id.data = movie.tag_id
        movieform.info.data = movie.info
        #  渲染 select textarea 标签
    if movieform.validate_on_submit():
        data = movieform.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash('影片已经存在', 'err')
            return redirect(url_for('admin.movie_edit',id=movie.id))

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')

        # 更改了url 资源，封面 资源

        if movieform.url.data:
            file_url = secure_filename(movieform.url.data.filename)
            movie.url = change_filename(file_url)
            movieform.url.data.save(app.config['UP_DIR'] + movie.url)

        if movieform.logo.data:
            file_logo = secure_filename(movieform.logo.data.filename)
            movie.logo = change_filename(file_logo)
            movieform.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.title = data['title']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']
        db.session.add(movie)
        db.session.commit()
        flash('修改电影成功','ok')
        return redirect(url_for('admin.movie_edit',id=movie.id))
    return render_template('admin/movie-edit.html',movieform=movieform,movie=movie)




# =======================预告==========================

@admin.route('/preview/add/',methods=['GET','POST'])
@admin_login_req
def preview_add():
    preview_form = PreviewForm()
    if preview_form.validate_on_submit():
        data = preview_form.data
        preview_count = Preview.query.filter_by(title=data['title']).count()

        if preview_count == 1:
            flash('预告已经存在','err')
            return redirect(url_for('admin.preview_add'))

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'],'rw')

        file_logo = secure_filename(preview_form.logo.data.filename)
        logo = change_filename(file_logo)
        preview_form.logo.data.save(app.config['UP_DIR']+logo)

        preview = Preview()
        preview.title = data['title']
        preview.logo = logo
        db.session.add(preview)
        db.session.commit()
        flash('增加预告成功','ok')
        return redirect(url_for('admin.preview_add'))

    return render_template('admin/preview-add.html',preview_form=preview_form)

# 预告列表
@admin.route('/preview/list/<int:page>/',methods=['GET'])
@admin_login_req
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page,per_page=5)

    return render_template('admin/preview-list.html',page_data=page_data)

# 删除预告
@admin.route('/preview/del/<int:id>/',methods=['GET'])
@admin_login_req
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash('删除预告成功','ok')
    return redirect(url_for('admin.preview_list',page=1))

# 编辑预告
@admin.route('/preview/edit/<int:id>/',methods=['GET','POST'])
@admin_login_req
def preview_edit(id=None):
    preview_form = PreviewForm()
    preview_form.logo.validators=[]  # 注意需要 清空 限制
    preview = Preview.query.get_or_404(int(id))
    if preview_form.validate_on_submit():
        data = preview_form.data
        preview_count = Preview.query.filter_by(title=data['title']).count()
        if preview.title != data['title'] and preview_count == 1:
            flash('预告已经存在','err')
            return redirect(url_for('admin.preview_edit',id=preview.id))

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'],'rw')

        if preview_form.logo.data:
            file_logo = secure_filename(preview_form.logo.data.filename)
            logo = change_filename(file_logo)
            preview_form.logo.data.save(app.config['UP_DIR']+logo)
            preview.logo = logo

        preview.title = data['title']

        db.session.add(preview)
        db.session.commit()

        flash('编辑成功','ok')

        return redirect(url_for('admin.preview_edit',id=preview.id))

    return render_template('admin/preview-add.html',preview_form=preview_form,preview=preview)



# ========================会员 管理==========================

# 用户列表
@admin.route('/user/list/<int:page>/',methods=['GET','POST'])
@admin_login_req
def user_list(page=None):
    if page is None:
        page =1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page,per_page=5)

    return render_template('admin/user-list.html',page_data=page_data)

# 用户详情
@admin.route('/user/detail/<int:id>/',methods=['GET'])
@admin_login_req
def user_detail(id=None):
    user = User.query.get_or_404(int(id))
    return render_template('admin/user-detail.html',user=user)

# 删除用户
@admin.route('/user/del/<int:id>/',methods=['GET','POST'])
@admin_login_req
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash('删除用户成功','ok')
    return redirect(url_for('admin.user_list',page=1))




# ==================== 评论 ===========================

@admin.route('/comments/list/<int:page>/',methods=['GET'])
@admin_login_req
def comments_list(page=None):
    if page is None:
        page = 1
    page =page
    page_data = Comment.query.order_by(Comment.addtime.desc()).paginate(page=page,per_page=5)
    return render_template('admin/comments-list.html',page_data=page_data,page=page)

@admin.route('/comments/del/<int:id>/<int:page>/',methods=['GET'])
@admin_login_req
def comments_del(id=None,page=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash('删除评论成功','ok')
    return redirect(url_for('admin.comments_list',page=page))





#  ==============  收藏电影 =====================

@admin.route('/moviecol/list/<int:page>/',methods=['GET'])
@admin_login_req
def moviecol_list(page=None):
    if page is None:
        page = 1
    page = page
    page_data = MovieCol.query.order_by(MovieCol.addtime.desc()).paginate(page=page,per_page=5)
    return render_template('admin/moviecol-list.html',page=page,page_data=page_data)

# 删除 收藏
@admin.route('/moviecol/del/<int:id>/<int:page>/',methods=['GET'])
@admin_login_req
def moviecol_del(id=None,page=None):
    moviecol = MovieCol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash('删除收藏成功！','ok')
    return redirect(url_for('admin.moviecol_list',page=page))







#   ================ 日志管理 =======================


@admin.route('/oplog/list/')
@admin_login_req
def oplog_list():
    return render_template('admin/oplog-list.html')






@admin.route('/adminlog/list/')
@admin_login_req
def adminlog_list():
    return render_template('admin/adminlog-list.html')

@admin.route('/userlog/list/')
@admin_login_req
def userlog_list():
    return render_template('admin/userlog-list.html')





# ============== 权限管理 ==================

# 添加权限
@admin.route('/auth/add/',methods=['GET','POST'])
@admin_login_req
def auth_add():
    auth_form = AuthForm()
    if auth_form.validate_on_submit():
        data = auth_form.data
        name = data['name']
        auth_count = Auth.query.filter_by(name=name).count()
        if auth_count == 1:
            flash('权限已经存在','err')
            return redirect(url_for('admin.auth_add'))
        url = data['url']
        auth = Auth(name=name,url=url)
        db.session.add(auth)
        db.session.commit()
        flash('添加权限成功','ok')
        return redirect(url_for('admin.auth_add'))
    return render_template('admin/auth-add.html',auth_form=auth_form)

#  权限列表
@admin.route('/auth/list/<int:page>/',methods=['GET','POST'])
@admin_login_req
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(Auth.addtime.desc()).paginate(page=page,per_page=5)
    return render_template('admin/auth-list.html',page_data=page_data)

# 权限删除
@admin.route('/auth/del/<int:id>/',methods=['GET','POST'])
@admin_login_req
def auth_del(id=None):
    auth = Auth.query.get_or_404(int(id))
    db.session.delete(auth)
    db.session.commit()
    flash('删除权限成功','ok')
    return redirect(url_for('admin.auth_list',page=1))

# 编辑权限
@admin.route('/auth/edit/<int:id>/',methods=['GET','POST'])
@admin_login_req
def auth_edit(id=None):
    auth_form = AuthForm()
    auth = Auth.query.get_or_404(int(id))
    if auth_form.validate_on_submit():
        data = auth_form.data
        auth_count = Auth.query.filter_by(name=data['name']).count()
        if auth.name != data['name'] and auth_count == 1:
            flash('权限已经存在','err')
            return redirect(url_for('admin.auth_list',page=1))

        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash('编辑权限成功','ok')
        return redirect(url_for('admin.auth_edit',id=auth.id))
    return render_template('admin/auth-add.html',auth_form=auth_form,auth=auth)




# ======================  角色管理 =========================

# 添加角色
@admin.route('/role/add/',methods=['GET','POST'])
@admin_login_req
def role_add():
    role_form = RoleForm()
    if role_form.validate_on_submit():
        data = role_form.data
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count == 1:
            flash('角色已经存在','err')
            return redirect(url_for('admin.role_add'))
        role = Role()
        role.name = data['name']
        role.auths = ';'.join(map(lambda i:str(i),data['auths'] ))
        db.session.add(role)
        db.session.commit()
        flash('角色创建成功','ok')
        return redirect(url_for('admin.role_add'))
    return render_template('admin/role-add.html',role_form=role_form)

# 角色列表
@admin.route('/role/list/<int:page>/',methods=['GET','POST'])
@admin_login_req
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(Role.addtime.desc()).paginate(page=page,per_page=5)
    return render_template('admin/role-list.html',page_data=page_data)

# 删除角色
@admin.route('/role/del/<int:id>/',methods=['GET'])
@admin_login_req
def role_del(id=None):
    role = Role.query.get_or_404(int(id))
    db.session.add(role)
    db.session.commit()
    flash('删除角色','ok')
    return redirect(url_for('admin.role_list',page=1))

# 编辑角色
@admin.route('/role/edit/<int:id>/',methods=['GET','POST'])
@admin_login_req
def role_edit(id=None):
    role_form = RoleForm()
    role = Role.query.get_or_404(int(id))

    if request.method == 'GET':
        role_form.auths.data = list(map(lambda i:int(i), role.auths.split(';')))
    if role_form.validate_on_submit():
        data = role_form.data
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count == 1 and role.name != data['name']:
            flash('角色已经存在','err')
            return redirect(url_for('admin.role_edit',id=role.id))
        role.name = data['name']
        role.auths = ';'.join(map(lambda i:str(i),data['auths']))
        db.session.add(role)
        db.session.commit()
        flash('编辑角色成功','ok')
        return redirect(url_for('admin.role_edit',id=role.id))
    return render_template('admin/role-add.html',role=role,role_form=role_form)



# 添加管理员
@admin.route('/admin/add/',methods=['GET','POST'])
@admin_login_req
def admin_add():
    admin_form = AdminForm()
    if admin_form.validate_on_submit():
        data = admin_form.data
        admin_count = Admin.query.filter_by(name=data['name']).count()
        if admin_count == 1:
            flash('管路员已经存在','err')
            return redirect(url_for('admin.admin_add'))
        from werkzeug.security import generate_password_hash
        admin = Admin(
            name = data['name'],
            pwd = generate_password_hash(data['pwd']),
            role_id = data['role_id']
        )
        db.session.add(admin)
        db.session.commit()
        flash('添加管理员成功','ok')
        return redirect(url_for('admin.admin_add'))
    return render_template('admin/admin-add.html',admin_form=admin_form)

# 管理员列表
@admin.route('/admin/list/<int:page>/',methods=['GET','POST'])
@admin_login_req
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.order_by(
        Admin.addtime.desc()
    ).paginate(page=page,per_page=5)

    return render_template('admin/admin-list.html',page_data=page_data)