from django.urls import path

from api import views

urlpatterns = [
    path("", views.ApiIndexView.as_view()),
    # system
    path("system/ping/", views.PingView.as_view()),
    path("system/health/", views.HealthView.as_view()),
    path("system/logs/", views.LogsView.as_view()),
    path("system/stream/", views.StreamView.as_view()),
    path("stats/overview/", views.OverviewView.as_view()),
    path("config/", views.ConfigView.as_view()),
    # events & analyses
    path("events/", views.EventListView.as_view()),
    path("events/live/", views.LiveEventsView.as_view()),
    path("events/ingest/", views.IngestView.as_view()),
    path("analyses/", views.AnalysisListView.as_view()),
    path("analyses/<uuid:pk>/", views.AnalysisDetailView.as_view()),
    # individual agents
    path("behavior/analyze/", views.BehaviorAnalyzeView.as_view()),
    path("behavior/users/", views.BehaviorUsersView.as_view()),
    path("behavior/users/<str:user_id>/", views.BehaviorUserView.as_view()),
    path("risk/analyze/", views.RiskAnalyzeView.as_view()),
    path("response/decide/", views.ResponseDecideView.as_view()),
    path("response/policy/", views.ResponsePolicyView.as_view()),
    path("agents/", views.AgentListView.as_view()),
    path("agents/status/", views.AgentListView.as_view()),
    path("agents/<str:name>/", views.AgentDetailView.as_view()),
    # attack simulation
    path("attacks/", views.AttackListView.as_view()),
    path("attacks/simulate/", views.AttackSimulateView.as_view()),
    # incidents (human-in-the-loop)
    path("incidents/", views.IncidentListView.as_view()),
    path("incidents/<int:pk>/", views.IncidentDetailView.as_view()),
    path("incidents/<int:pk>/decision/", views.IncidentDecisionView.as_view()),
    # ML
    path("ml/evaluation/", views.EvaluationView.as_view()),
]
