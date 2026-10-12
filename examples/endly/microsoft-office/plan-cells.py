import json
import re
import sys
# Emits a plan only. Execution remains with Endly/MCP.
def validate_settings(settings):
 required = {'processId','processStartToken','windowId','windowTitle','caseId','startRow','startColumn','rows'}
 if not isinstance(settings,dict) or set(settings) != required:
  raise ValueError('Supply exactly the documented Excel cell parameters')
 for field,maximum in [('processId',2147483647),('windowId',4294967295),('startRow',1048576)]:
  if type(settings[field]) is not int or not 0 < settings[field] <= maximum:
   raise ValueError(field+' must be a positive bounded integer')
 for field in ['processStartToken','windowTitle','caseId','startColumn']:
  value=settings[field]
  if not isinstance(value,str) or not value.strip() or len(value.encode('utf-8')) > 255 or any(ord(c)<32 or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in value):
   raise ValueError(field+' must be bounded single-line text')
 if not re.fullmatch(r'[1-9][0-9]*:[0-9]+',settings['processStartToken']):
  raise ValueError('A freshly discovered process birth token is required')
 col=settings['startColumn'];rows=settings['rows']
 if not re.fullmatch(r'[A-Z]',col) or not isinstance(rows,list) or not rows or not isinstance(rows[0],list):
  raise ValueError('Require a rectangular block within columns A...Z')
 width=len(rows[0])
 if not 1<=width<=26 or len(rows)*width>100 or ord(col)+width-1>ord('Z') or any(not isinstance(row,list) or len(row)!=width for row in rows):
  raise ValueError('Require a rectangular block of 1...100 cells within columns A...Z')
 # Return commits move to the following row, which must also be addressable.
 if settings['startRow']+len(rows)>1048576:
  raise ValueError('Block and final commit position must remain within the Excel sheet')
 if any(not isinstance(value,str) or not value or len(value.encode('utf-8'))>4096 or any(ord(c)<32 or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in value) for row in rows for value in row):
  raise ValueError('Require nonempty bounded single-line strings')


def build(settings):
 validate_settings(settings)
 s={'kind':'native','bundleId':'com.microsoft.Excel','processId':settings['processId'],'processStartToken':settings['processStartToken']}
 window_id=settings['windowId']; title=settings['windowTitle']; case=settings['caseId']
 first_row=settings['startRow']; first_col=settings['startColumn'];rows=settings['rows']
 window_expr='office.window(title: '+json.dumps(title)+')'
 def st(v):return {'kind':'string','string':v}
 def pred(identifier,text,focus=False,attribute='value'):
  inputs={'bundleID':st(s['bundleId']),'processId':{'kind':'number','number':s['processId']},'processStartToken':st(s['processStartToken']),'strategy':st('id'),'selector':st(identifier),'attribute':st(attribute),'expected':st(text)}
  inputs.update({'nativeRoot':st('focusedElement')} if focus else {'windowTitle':st(title)})
  return {'kind':'adapter','adapter':'native','name':'valueEquals','scope':{'surfaceRef':'office'},'timeoutMs':7000,'freshnessMs':1000,'requiredAuthority':'observational','inputs':inputs}
 steps=[{'id':'activate','command':'office.activate()','effect':{'businessKey':{'task':st(case+'-activate')}}}]
 def key(id,k,post,pre=None):
  step={'id':id,'command':f'office.pressWindowKey(windowId: {window_id}, key: {json.dumps(k)})','timeoutMs':15000,'postcondition':post,'effect':{'businessKey':{'task':st(case),'step':st(id)},'reconcile':post}}
  if pre:step['precondition']=pre
  steps.append(step)
 columns=[(chr(ord(first_col)+i),[row[i] for row in rows]) for i in range(len(rows[0]))]
 for ci,(col,values) in enumerate(columns):
  if ci:
   previous=columns[ci-1][0]
   for row in range(first_row+len(rows)-1,first_row-1,-1):key('up-'+col+str(row),'ArrowUp',pred('NameBox',previous+str(row)))
   key('right-'+col,'ArrowRight',pred('NameBox',col+str(first_row)))
  for row,text in enumerate(values,first_row):
   addr=col+str(row)
   key('edit-'+addr,'Control+U',pred('XLIncellEditor','XLIncellEditor',True,'identifier'),pred('NameBox',addr))
   p=pred('XLFormulaEditor',text)
   steps.append({'id':'text-'+addr,'command':f'office.typeWindowText(windowId: {window_id}, text: {json.dumps(text)}, focusRole: "AXTextArea", focusIdentifier: "XLIncellEditor")','timeoutMs':15000,'precondition':pred('XLFormulaEditor',''),'postcondition':p,'effect':{'businessKey':{'task':st(case),'cell':st(addr),'text':st(text)},'reconcile':p}})
   key('commit-'+addr,'Return',pred('NameBox',col+str(row+1)))
 plan={'schemaVersion':1,'name':'Populate verified disposable sales source table','surfaces':{'office':s},'requires':{'adapters':['native']},'steps':steps}
 return plan


if __name__ == '__main__':
 try:
  json.dump(build(json.load(sys.stdin)),sys.stdout,indent=2);print()
 except (ValueError,TypeError,KeyError) as error:
  raise SystemExit(str(error))
