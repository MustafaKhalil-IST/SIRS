from django.urls import path, include
from . import views



urlpatterns = [
	path('signup', views.signup, name='signup'),
	path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 
	views.activate, name='activate')
]
