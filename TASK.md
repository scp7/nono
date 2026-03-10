# Task

**Run:** `20260310_073541_351164`
**Branch:** `swarm/job-20260310_073541_351164`
**Repo:** `git@github.com:scp7/nono-copy`
**Issue:** `always-further/nono#98`

---

## GitHub Issue: always-further/nono#98

Feature request: integrate with gh-aw-firewall - limit app access to internet

I'd like to be able to granularly limit the websites my isolated application or an agent is allowed to access, for example, by proxying network traffic via gh-aw-firewall via CLI or container.

This leverages Squid proxy with granular HTTP traffic filtering capable of blocking individual blocks of an HTML page.

https://github.com/github/gh-aw-firewall/blob/main/docs/quickstart.md



enhancement

We have a plan emerging for this, landlock will shutdown access to everything apart from localhost where a proxy will run in a parent process , I have the worked deferred until the core library comes in around a week or so. 
---
Proxy has delivered this capability. Keeping this open as would like to explore how nono+proxy can be used to deliver github actions
---
@scp7 would you be so kind as to provide an example on how I can configure and utilize a proxy with nono to granularly filter HTTP traffic?
For example if I wanted to remove JS code or images from a web page, so my agent would not have access to those.

---

Assess and see if issue has been fixed
