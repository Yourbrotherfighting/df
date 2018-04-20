from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from django.views.generic import View
from django.http import HttpResponse
from django.conf import settings

from apps.user.models import User
from celery_tasks.tasks import send_register_active_email
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
from utils.mixin import LoginRequiredMixin
import re


# Create your views here.



# /user/register
def register(request):
    '''显示注册页面页面'''
    if request.method == 'GET':
        # 显示注册页面页面
        return render(request, 'register.html')
    else:
        # 进行注册处理
        # 接受数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 2,数据校验
        if not all([username, password, email]):  # all方法里是一个列表
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不对'})
        # 是否同意协议
        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user:
            return render(request, 'register.html', {'errmsg': '用户名已经存在'})
        # 3,业务处理
        # create_user  django内置的认证系统
        user = User.objects.create_user(username, email, password)  # User具体的实现是怎样的
        user.is_active = 0
        user.save()

        # 4,返回应答，跳转到商品首页
        return redirect(reverse('goods:index'))


def register_handle(request):
    '''进行注册处理'''
    # 1,接受数据
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    email = request.POST.get('email')
    allow = request.POST.get('allow')

    # 2,数据校验
    if not all([username, password, email]):  # all方法里是一个列表
        # 数据不完整
        return render(request, 'register.html', {'errmsg': '数据不完整'})

    # 校验邮箱
    if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
        return render(request, 'register.html', {'errmsg': '邮箱格式不对'})
    # 是否同意协议
    if allow != 'on':
        return render(request, 'register.html', {'errmsg': '请同意协议'})
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        user = None

    if user:
        return render(request, 'register.html', {'errmsg': '用户名已经存在'})
    # 3,业务处理
    # create_user  django内置的认证系统
    user = User.objects.create_user(username, email, password)  # User具体的实现是怎样的
    user.is_active = 0
    user.save()

    # 4,返回应答，跳转到商品首页
    return redirect(reverse('goods:index'))


# /user/register
class RegisterView(View):
    '''注册'''

    def get(self, request):
        '''显示注册页面'''
        return render(request, 'register.html')

    def post(self, request):
        '''进行注册处理'''
        # 1,接受数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 2,数据校验
        if not all([username, password, email]):  # all方法里是一个列表
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不对'})
        # 是否同意协议
        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 查询数据库中是否已经有用户名
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user:
            return render(request,'register.html', {'errmsg': '用户名已经存在'})

        # 3,业务处理
        # create_user  django内置的认证系统
        user = User.objects.create_user(username, email, password)  # 为什么返回用户名已经存在，还会存入数据库
        user.is_active = 0
        user.save()

        # 发送激活邮件，包含激活链接:http://127.0.0.1:8000/user/active/3
        # 激活信息包含用户的身份信息，并且加密身份信息

        # 加密身份信息，生成激活token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm': user.id}
        token = serializer.dumps(info)
        token = token.decode()

        # send_mail(subject, message, sender, receiver,html_message=html_message)
        # 发送邮件 使用delay函数
        send_register_active_email.delay(email, username, token)

        # 4,返回应答，跳转到商品首页
        return redirect(reverse('goods:index'))


class ActiveView(View):
    '''用户激活'''

    def get(self, request, token):
        '''进行用户激活'''
        serializer = Serializer(settings.SECRET_KEY, 3600)
        # print(request.user.is_active)
        try:
            info = serializer.loads(token)
            # 获取激活用户的ID
            user_id = info['confirm']

            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            # print(request.user.is_active)
            user.is_active = 1
            user.save()

            # 跳转到登录页面
            return redirect(reverse('user:login'))

        except SignatureExpired as e:
            # 激活链接已经过期
            return HttpResponse('激活链接已经过期')


class LoginView(View):
    '''登录'''

    def get(self, request):
        '''显示登录页面'''
        # 判断是否记住了用户名
        if 'username' in request.COOKIES:
            username = request.COOKIES.get('username')
            checked = 'checked'
        else:
            username = ''
            checked = ''
        return render(request, 'login.html', {'checked': checked, 'username': username})

    def post(self, request):
        '''登录处理'''
        # 获取数据
        username = request.POST.get('username')
        password = request.POST.get('pwd')
        # remember = request.POST.get('remember')


        # 数据校验
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg': '数据不完整'})

        # 业务处理:登录校验
        user = authenticate(username=username, password=password)
        if user is not None:
            # 用户名密码正确
            if user.is_active:
                # 用户已经激活
                # 记住用户的登录状态
                login(request, user)

                # 获取登录后要跳转的地址,默认跳转到首页
                next_url = request.GET.get('next',reverse('goods:index'))  # None

                # 跳转到next_url
                response = redirect(next_url)


                # 判断是否需要记住用户名
                remember = request.POST.get('remember')
                if remember == 'on':
                    response.set_cookie('username', username, max_age=7 * 24 * 3600)
                else:
                    response.delete_cookie('username')
                return response
                # next_usr =  request.GET.get('next',reverser('goods:index'))
            else:
                # 用户没有激活
                return render(request, 'login.html', {'errmsg': '账户没有被激活'})

        else:
            # 用户名或密码错误
            return render(request, 'login.html', {'errmsg': '用户名或密码错误'})


            # 返回数据


class UserInfoView(LoginRequiredMixin,View):
    """用户中心－信息页"""
    def get(self,request):
        '''显示'''
        # page':'user'
        return render(request,'user_center_info.html',{'page':'user'})


class UserOrderView(LoginRequiredMixin,View):
    """用户中心－订单页"""
    def get(self,request):
        '''显示'''
        # 'page':'order'
        return render(request,'user_center_order.html',{'page':'order'})


class AddressView(LoginRequiredMixin,View):
    """用户中心－地址"""
    def get(self,request):
        '''显示'''
        # 'page':'address'  选中高亮
        return render(request,'user_center_site.html',{'page':'address'})