"""Emit a recent-file reopen plan; caller must freshly prove closure and uniqueness."""
import json
import re
import sys

def build(settings):
    required = {'processId','processStartToken','windowTitle','recentFileName','expectedSheet','caseId'}
    if not isinstance(settings,dict) or set(settings) != required:
        raise ValueError('Supply exactly the documented reopen parameters')
    if type(settings['processId']) is not int or not 0 < settings['processId'] <= 2147483647:
        raise ValueError('Fresh process ID required')
    for field in required - {'processId'}:
        value=settings[field]
        if not isinstance(value,str) or not value.strip() or len(value.encode())>255 or any(ord(c)<32 or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in value):
            raise ValueError('Bounded single-line '+field+' required')
    if not re.fullmatch(r'[1-9][0-9]*:[0-9]+',settings['processStartToken']):
        raise ValueError('Fresh kernel birth token required')
    if not settings['recentFileName'].endswith('.xlsx') or '/' in settings['recentFileName'] or '\\' in settings['recentFileName']:
        raise ValueError('Observed exact XLSX recent-file basename required')
    st=lambda value:{'kind':'string','string':value}
    surface={'kind':'native','bundleId':'com.microsoft.Excel','processId':settings['processId'],'processStartToken':settings['processStartToken']}
    predicate={'kind':'adapter','adapter':'native','name':'valueEquals','scope':{'surfaceRef':'excel'},'timeoutMs':10000,'freshnessMs':1000,'requiredAuthority':'observational','inputs':{'bundleID':st(surface['bundleId']),'processId':{'kind':'number','number':surface['processId']},'processStartToken':st(surface['processStartToken']),'windowTitle':st(settings['windowTitle']),'strategy':st('id'),'selector':st(settings['expectedSheet']),'attribute':st('identifier'),'expected':st(settings['expectedSheet'])}}
    return {'schemaVersion':1,'name':'Reopen independently checked Excel workbook through fresh unique recent-file entry','surfaces':{'excel':surface},'requires':{'adapters':['native']},'steps':[{'id':'reopen','command':'excel.getByName('+json.dumps(settings['recentFileName'])+', exact: true).click()','postcondition':predicate,'effect':{'businessKey':{'case':st(settings['caseId']),'recentFile':st(settings['recentFileName']),'expectedSheet':st(settings['expectedSheet'])},'reconcile':predicate}}]}

if __name__=='__main__':
    try:json.dump(build(json.load(sys.stdin)),sys.stdout,indent=2);print()
    except (ValueError,TypeError,KeyError) as error:raise SystemExit(str(error))
