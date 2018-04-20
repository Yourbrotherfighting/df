from django.shortcuts import render

# Create your views here.
def index(request):
    '''显示商品首页'''
    return render(request,'index.html')