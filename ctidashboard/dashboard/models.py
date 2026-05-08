from django.db import models


class IOC(models.Model):
    IOC_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('hash', 'File Hash'),
    ]

    value = models.CharField(max_length=256, unique=True)
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.value


class IOCAnalysis(models.Model):
    ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name="analyses")

    score = models.IntegerField()
    verdict = models.CharField(max_length=50)
    mitre = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ioc.value} - {self.verdict}"


class IOCSource(models.Model):
    analysis = models.ForeignKey(IOCAnalysis, on_delete=models.CASCADE, related_name="sources")

    source_name = models.CharField(max_length=100)
    raw_data = models.JSONField()

    score = models.FloatField(null=True, blank=True)
    link = models.URLField(null=True, blank=True)

    def __str__(self):
        return f"{self.source_name} - {self.analysis.ioc.value}"
    
    
class IOCRecord(models.Model):
    ioc = models.CharField(max_length=255)
    ioc_type = models.CharField(max_length=20)
    source = models.CharField(max_length=100)
    score = models.IntegerField()
    link = models.URLField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ioc} ({self.ioc_type})"