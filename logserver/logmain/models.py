# -*- coding: utf-8 -*-

"""
	Copyright (C) 2019  Soheil Khodayari, IMDEA Software
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	Description:
	---------------
    Django models for each COSI attack class.
"""

from __future__ import unicode_literals

from django.db import models

 

# --------------------------------------------------------------------------------- #
#			postMessage Attack Class
# --------------------------------------------------------------------------------- #


class PostMessageRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "PostMessageTest on {0} with hashId={1}".format(self.timestamp, self.hashId)

class PostMessageData(models.Model):

	OPEN_MODE_CHOICES = (
        ('0', 'frame'),
        ('1', 'window'),
    )
	# pk (created internally)
	run = models.ForeignKey("PostMessageRun", on_delete=models.CASCADE, related_name = "postMessages")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=1000)
	openType = models.CharField(max_length=1, choices=OPEN_MODE_CHOICES)


class PostMessageDataElement(models.Model):
	messageData = models.ForeignKey("PostMessageData", on_delete=models.CASCADE, related_name = "elements")
	message = models.TextField(blank=True, null = True)

	def __unicode__(self):
		return self.message

	def save(self, *args, **kwargs):
		self.message = self.message.replace("\"", "'")
		super(PostMessageDataElement, self).save(*args, **kwargs)


# --------------------------------------------------------------------------------- #
#			Events Fired Attack Class
# --------------------------------------------------------------------------------- #

class EventFireCountRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "EventFireCountTest on {0} with hashId={1}".format(self.timestamp, self.hashId)

class EventFireCountData(models.Model):

	AUTH_CHOICES = (
        ('0', 'Not Logged In'),
        ('1', 'Logged In'),
        ('2', 'Fresh Browser'),
    )
	# pk (created internally)
	run = models.ForeignKey("EventFireCountRun", on_delete=models.CASCADE, related_name = "events")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	tag_name = models.CharField(max_length=200)
	event_order = models.CharField(max_length=1000)
	event_count = models.CharField(max_length=1000)

	class Meta:
		unique_together = ("run", "siteId", "url", "stateLabel", "tag_name", "event_order", "event_count")

	def save(self, *args, **kwargs):
		self.event_order = self.event_order.replace("\"", "")
		self.event_count = self.event_count.replace("\"", "")
		super(EventFireCountData, self).save(*args, **kwargs)

	def __unicode__(self):
		return "EFC-SiteId=%s-URL=%s-hash=%s"%(self.siteId, self.url, self.run.hashId)



# --------------------------------------------------------------------------------- #
#			Content Window (Cross Domain Frame Count Leakage)
# --------------------------------------------------------------------------------- #

class ContentWindowRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "ContentWindowTest on {0} with hashId={1}".format(self.timestamp, self.hashId)

class ContentWindowData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("ContentWindowRun", on_delete=models.CASCADE, related_name = "datas")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	cwCount = models.CharField(max_length=1000)

	class Meta:
		unique_together = ("run", "siteId", "url", "stateLabel", "cwCount")


# --------------------------------------------------------------------------------- #
#			Content Security Policy Attack Class
# --------------------------------------------------------------------------------- #


class CSPRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "ContentWindowTest on {0} with hashId={1}".format(self.timestamp, self.hashId)

class CSPData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("CSPRun", on_delete=models.CASCADE, related_name = "csp_datas")
	siteId = models.IntegerField()
	targetURL = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	tagName = models.CharField(max_length=300)

	class Meta:
		unique_together = ("run", "siteId", "targetURL", "stateLabel", "tagName")

class CSPDataViolatedURL(models.Model):
	CSPData = models.ForeignKey("CSPData", on_delete=models.CASCADE, related_name = "violated_urls")
	violatedURL  = models.CharField(max_length=2000)

	def __unicode__(self):
		return self.violatedURL

	def __str__(self):
		return self.violatedURL

	def __repr__(self):
		return self.violatedURL



# --------------------------------------------------------------------------------- #
#			Script Errors and Script Variables
# --------------------------------------------------------------------------------- #


class ScriptRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300)
	attackMode = models.IntegerField() # 0 for script variables, 1 for script errors
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	class Meta:
		unique_together = ("hashId", "attackMode")

	def __unicode__(self):
		return "ScriptAttack on {0} with hashId={1}".format(self.timestamp, self.hashId)

class ScriptData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("ScriptRun", on_delete=models.CASCADE, related_name = "script_datas")
	siteId = models.IntegerField()
	targetURL = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	message = models.CharField(max_length=300)
	messageLength= models.IntegerField(default=0)

	class Meta:
		unique_together = ("run", "siteId", "targetURL", "stateLabel", "message", "messageLength")

	def __unicode__(self):
		return self.message

	def __str__(self):
		return self.message

	def __repr__(self):
		return self.message


# --------------------------------------------------------------------------------- #
#			Timing Analysis Attack Class
# --------------------------------------------------------------------------------- #

class TimingAnalysisRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "TimingAnalysisTest on {0} with hashId={1}".format(self.timestamp, self.hashId)

class TimingAnalysisData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("TimingAnalysisRun", on_delete=models.CASCADE, related_name = "ta_datas")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	tag_name = models.CharField(max_length=200)
	elpased_time = models.CharField(max_length=1000)

	class Meta:
		unique_together = ("run", "siteId", "url", "stateLabel", "tag_name", "elpased_time")

	def save(self, *args, **kwargs):
		self.elpased_time = self.elpased_time.replace("\"", "")
		super(TimingAnalysisData, self).save(*args, **kwargs)

	def __unicode__(self):
		return "TA-SiteId=%s-URL=%s-hash=%s"%(self.siteId, self.url, self.run.hashId)

# --------------------------------------------------------------------------------- #
#				CORS Attack Class
# --------------------------------------------------------------------------------- #

class CORSRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "CORS-Test on {0} with hashId={1}".format(self.timestamp, self.hashId)

class CORSData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("CORSRun", on_delete=models.CASCADE, related_name = "cors_datas")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	response = models.CharField(max_length=1000)

	class Meta:
		unique_together = ("run", "siteId", "url", "stateLabel", "response")

	def save(self, *args, **kwargs):
		self.response = self.response.replace("\"", "")
		super(CORSData, self).save(*args, **kwargs)

	def __unicode__(self):
		return "CORS-SiteId=%s-URL=%s-hash=%s"%(self.siteId, self.url, self.run.hashId)

# --------------------------------------------------------------------------------- #
#				Object Properties Attack Class
# --------------------------------------------------------------------------------- #

class ObjectReadPropertiesRun(models.Model):
	# pk (created internally)
	timestamp = models.CharField(max_length=300, blank= True, null = True)
	hashId = models.CharField(max_length=300, unique = True)
	Browser = models.CharField(max_length=300, default="Chrome", blank=True, null=True )
	BrowserVersion = models.CharField(max_length=300, blank=True, null=True)

	def __unicode__(self):
		return "ObjectReadPropertiesRun on {0} with hashId={1}".format(self.timestamp, self.hashId)

class ObjectReadPropertiesData(models.Model):

	# pk (created internally)
	run = models.ForeignKey("ObjectReadPropertiesRun", on_delete=models.CASCADE, related_name = "datas")
	siteId = models.IntegerField()
	url = models.CharField(max_length=2000)
	stateLabel = models.CharField(max_length=200)
	tag_name = models.CharField(max_length=200)
	props = models.CharField(max_length=2000)

	class Meta:
		unique_together = ("run", "siteId", "url", "stateLabel", "tag_name", "props")

	def save(self, *args, **kwargs):
		self.props = self.props.replace("\"", "")
		super(ObjectReadPropertiesData, self).save(*args, **kwargs)