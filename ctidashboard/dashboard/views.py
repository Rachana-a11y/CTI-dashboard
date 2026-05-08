# from django.shortcuts import render, redirect
# from rest_framework.decorators import api_view
# from rest_framework.response import Response

# from collections import Counter
# import json
# import plotly
# import plotly.graph_objs as go

# from .models import IOC, IOCAnalysis, IOCSource
# from .utils import detect_ioc_type, is_valid_ioc, normalize_ioc
# from services.ioc_service import process_ioc
# from .api_clients import fetch_crtsh, fetch_securitytrails, fetch_abuseipdb


# def ioc_input(request):
#     error = None

#     if request.method == "POST":
#         ioc = normalize_ioc(request.POST.get("ioc", ""))

#         if not is_valid_ioc(ioc):
#             error = "Invalid IOC format"
#         else:
#             result = process_ioc(ioc)

#             ioc_obj, _ = IOC.objects.get_or_create(
#                 value=ioc,
#                 defaults={"ioc_type": result["type"]}
#             )

#             analysis = IOCAnalysis.objects.create(
#                 ioc=ioc_obj,
#                 score=result["score"],
#                 verdict=result["verdict"],
#                 mitre=result["mitre"]
#             )

#             IOCSource.objects.create(
#                 analysis=analysis,
#                 source_name="VirusTotal",
#                 raw_data=result["vt"],
#                 score=result["vt"].get("malicious"),
#                 link=result["vt"].get("link")
#             )

#             IOCSource.objects.create(
#                 analysis=analysis,
#                 source_name="AbuseIPDB",
#                 raw_data=result["abuse"],
#                 score=result["abuse"].get("abuseConfidenceScore"),
#                 link=result["abuse"].get("link")
#             )

#             IOCSource.objects.create(
#                 analysis=analysis,
#                 source_name="OTX",
#                 raw_data=result["otx"],
#                 score=result["otx"].get("pulse_count"),
#                 link=result["otx"].get("link")
#             )

#             request.session["ioc"] = ioc
#             return redirect("results")

#     return render(request, "ioc_app/ioc_input.html", {"error": error})


# def results(request):
#     analyses = IOCAnalysis.objects.select_related("ioc").order_by("-created_at")[:15]
#     return render(request, "ioc_app/results.html", {"analyses": analyses})


# def dnsgraph(request):
#     return render(request, "ioc_app/dnsgraph.html", {
#         "ioc": request.session.get("ioc")
#     })


# @api_view(['GET'])
# def dnsgraph_api(request):
#     ioc = request.GET.get("ioc")
#     if not ioc:
#         return Response({"error": "No IOC provided"}, status=400)

#     ioc_type = detect_ioc_type(ioc)

#     nodes = {ioc: {"id": ioc}}
#     edges = []

#     if ioc_type == "domain":
#         subs = fetch_crtsh(ioc) or fetch_securitytrails(ioc)

#         for sub in subs:
#             nodes[sub] = {"id": sub}
#             edges.append({"data": {"source": ioc, "target": sub}})

#     elif ioc_type == "ip":
#         base = ".".join(ioc.split(".")[:3])
#         for i in range(1, 5):
#             ip = f"{base}.{i}"
#             nodes[ip] = {"id": ip}
#             edges.append({"data": {"source": ioc, "target": ip}})

#     return Response({"elements": [{"data": v} for v in nodes.values()] + edges})


# @api_view(['GET'])
# def ioc_api(request):
#     data = IOCAnalysis.objects.select_related("ioc")[:20]

#     return Response([
#         {
#             "ioc": d.ioc.value,
#             "type": d.ioc.ioc_type,
#             "score": d.score,
#             "verdict": d.verdict
#         }
#         for d in data
#     ])


# def charts(request):
#     analyses = IOCAnalysis.objects.select_related("ioc")

#     type_counts = Counter(a.ioc.ioc_type for a in analyses)

#     chart = {
#         "data": [go.Pie(labels=list(type_counts.keys()), values=list(type_counts.values()))]
#     }

#     return render(request, "ioc_app/charts.html", {
#         "chart_data": json.dumps(chart, cls=plotly.utils.PlotlyJSONEncoder)
#     })


from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from .models import IOCRecord
from .utils import normalize_ioc, detect_ioc_type, is_valid_ioc
from services.ioc_service import analyze_ioc
import csv


def dashboard(request):
    return render(request, "ioc_app/dashboard.html")


def ioc_input(request):
    if request.method == "POST":
        raw_ioc = request.POST.get("ioc")
        ioc = normalize_ioc(raw_ioc)

        if not is_valid_ioc(ioc):
            return render(request, "ioc_app/ioc_input.html", {
                "error": "Invalid IOC format!"
            })

        ioc_type = detect_ioc_type(ioc)
        result = analyze_ioc(ioc, ioc_type)

        IOCRecord.objects.create(
            ioc=ioc,
            ioc_type=ioc_type,
            source=result["source"],
            score=result["score"],
            link=result["link"]
        )

        return redirect("results")

    return render(request, "ioc_app/ioc_input.html")


def results(request):
    records = IOCRecord.objects.all().order_by("-timestamp")[:20]

    stats = {
        "malicious": IOCRecord.objects.filter(score__gt=70).count(),
        "suspicious": IOCRecord.objects.filter(score__range=(40, 70)).count(),
        "harmless": IOCRecord.objects.filter(score__lt=40).count(),
    }

    return render(request, "ioc_app/results.html", {
        "records": records,
        "stats": stats
    })


def charts(request):
    records = IOCRecord.objects.all()

    category_counts = {}
    dates = []
    scores = []

    for r in records:
        category_counts[r.ioc_type] = category_counts.get(r.ioc_type, 0) + 1
        dates.append(r.timestamp.strftime("%Y-%m-%d"))
        scores.append(r.score)

    chart_data = {
        "category": {
            "data": [{
                "labels": list(category_counts.keys()),
                "values": list(category_counts.values()),
                "type": "pie"
            }],
            "layout": {"title": "IOC Category Distribution"}
        },
        "timeline": {
            "data": [{
                "x": dates,
                "y": scores,
                "type": "scatter"
            }],
            "layout": {"title": "Threat Score Timeline"}
        }
    }

    return render(request, "ioc_app/charts.html", {
        "chart_data": chart_data
    })


def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="ioc_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['IOC', 'Type', 'Score', 'Source'])

    for r in IOCRecord.objects.all():
        writer.writerow([r.ioc, r.ioc_type, r.score, r.source])

    return response


def dns_graph_api(request):
    ioc = request.GET.get("ioc")

    elements = [
        {"data": {"id": ioc, "type": "root"}},
        {"data": {"id": "sub."+ioc, "type": "subdomain"}},
        {"data": {"id": "8.8.8.8", "type": "related"}},
        {"data": {"source": ioc, "target": "sub."+ioc}},
        {"data": {"source": ioc, "target": "8.8.8.8"}},
    ]

    return JsonResponse({
        "elements": elements,
        "source": "Generated"
    })


def dns_graph_page(request):
    ioc = request.GET.get("ioc", "")
    return render(request, "ioc_app/dnsgraph.html")


