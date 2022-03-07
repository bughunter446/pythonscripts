import sys, os, csv, re, ipaddress, socket
from lxml import etree as ET
from lxml.html import fromstring, tostring
# pip3 install xlrd to read_excel
#from pptx.dml.color import RGBColor
# pip3 install python-pptx not pip3 install pptx
#from cvss import CVSS2, CVSS3
import pandas as pd
import numpy as np
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', -1)
import time
import html

# Create a 'ConsolidatedResultsByTitle-<folder>.xlsx' in same folder as inputFile
def mergeconsolidatebytitle(inputFile):
    (baseFolder, basename)=os.path.split(inputFile)
    print('baseFolder: ', baseFolder) # G:\scanners
    print('basename: ', basename) # ConsolidatedResults.xlsx
    (baseFolder2, foldername)=os.path.split(baseFolder)
    print('baseFolder2: ', baseFolder2) # G:\
    print('foldername: ', foldername) # scanners
    (filename, fileext)=os.path.splitext(basename)
    print('filename: ', filename) # ConsolidatedResults
    print('fileext: ', fileext) # .xlsx
    #baseFolder=path2
    timestr = time.strftime("%Y%m%d-%H%M%S")
    outputFile1=os.path.join(baseFolder, 'ConsolidatedResultsByTitle-'+foldername+basename+'_'+timestr+'.xlsx')
    print('outputFile1: ',outputFile1)
    #outputFile1=inputFile
    writer2=pd.ExcelWriter(outputFile1)

    # Read from INput File
    #xl=pd.ExcelFile(inputFile,engine='openpyxl')
    #dfvulns = xl.parse('Raw')
    dfvulns = pd.read_csv(inputFile)

    
    dfvulns.to_excel(writer2, sheet_name='Raw')



    # Cannot include Exploits here because it is inconsistent and may result in duplidate output
    #outputcols=['Rule Title','Region','Resource Type','Resource','Resource Name','Notes','Description','Implication',
    #'Recommendation','References','Account','Severity','Status','Account GID','Scoring']
    outputcols=['complianceStandard','complianceControl','complianceControlName','recommendationDisplayName','description','remediationSteps','state','notApplicableReason','azurePortalRecommendationLink','complianceState','subscriptionId','subscriptionName','resourceType','resourceName','resourceId','severity']


    dfvulnsbytitle=dfvulns[outputcols]

    # Reading from excel will have NA for blank 'Test Output' which will cause error
    # TypeError: '<' not supported between instances of 'str' and 'float'
    dfvulnsbytitle=dfvulnsbytitle.fillna('')
    # Remove [New] from issue titles
    #dfvulnsbytitle['Rule Title']=dfvulnsbytitle['Rule Title'].map(lambda x: x.split('[New] ')[-1])

    # Consolidate Issues by Subscriptions
    # Note complianceState refers to overall compliance of of Control
    # within a control, PASSED = all healthy/NA resources, FAIlED=contain unhealthy resources
    # Multiple <'complianceControl','complianceControlName'> can have the same <'recommendationDisplayName','description','remediationSteps'>
    groupedbycols = ['recommendationDisplayName','subscriptionName','subscriptionId','complianceStandard','complianceControl','complianceControlName','complianceState','resourceType','description','remediationSteps','severity','state','notApplicableReason']
    tocombine = []
    tocombinecrlf = ['resourceId','resourceName','azurePortalRecommendationLink']
    tocombinecomma = []
    tocombinemax = []        
    #dfvulnsbytitle=dfvulnsbytitle.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle=dfvulnsbytitle.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle[tocombinecrlf]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecrlf].transform(lambda x: '\n* '.join(sorted(x.unique()))))

    #dfvulnsbytitle[tocombinecomma]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecomma].transform(lambda x: ','.join(sorted(x.unique()))))

    dfvulnsbytitle['resourceId']=dfvulnsbytitle['subscriptionName']+' ('+dfvulnsbytitle['subscriptionId']+')'+'\n* '+dfvulnsbytitle['resourceId']
    dfvulnsbytitle['resourceName']=dfvulnsbytitle['subscriptionName']+' ('+dfvulnsbytitle['subscriptionId']+')'+'\n* '+dfvulnsbytitle['resourceName']
    #dfvulnsbytitle['Notes']=dfvulnsbytitle['subscriptionId']+'\n* '+dfvulnsbytitle['Notes']

    dfvulnsbytitle2=dfvulnsbytitle[['complianceStandard','complianceControl','complianceControlName','recommendationDisplayName','description','remediationSteps','complianceState','subscriptionId','subscriptionName','resourceType','resourceName','resourceId','severity','azurePortalRecommendationLink']]
    
    # Consolidate Issues By Title and Resource State
    groupedbycols = ['complianceStandard','complianceState','resourceType','recommendationDisplayName','description','remediationSteps','state','notApplicableReason']
    tocombinecrlf = ['subscriptionId','subscriptionName','resourceId','resourceName','azurePortalRecommendationLink','complianceControl','complianceControlName','severity']
    dfvulnsbytitle=dfvulnsbytitle.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle[tocombinecrlf]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecrlf].transform(lambda x: '\n'.join(sorted(x.unique()))))

    # Output to Excel
    dfvulnsbytitle[outputcols].drop_duplicates().reset_index(drop=True).to_excel(writer2, sheet_name='ConsolidatedByState', index=False)

    # Consolidate Issues by Title, Ignoring State of resources ( 'state','notApplicableReason' )
    outputcols2=['complianceStandard','complianceControl','complianceControlName','recommendationDisplayName','description','remediationSteps','severity','complianceState']
    dfvulnsbytitle2=dfvulns[outputcols2]
    dfvulnsbytitle2=dfvulnsbytitle2.fillna('')
    dfvulnsbytitle2=dfvulnsbytitle2[dfvulnsbytitle2['complianceState']=='Failed']
    groupedbycols = ['recommendationDisplayName','description','remediationSteps']
    tocombinecrlf = ['complianceStandard','complianceControl','complianceControlName','severity','complianceState']
    dfvulnsbytitle2=dfvulnsbytitle2.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle2[tocombinecrlf]=pd.DataFrame(dfvulnsbytitle2.groupby(groupedbycols)[tocombinecrlf].transform(lambda x: '\n'.join(sorted(x.unique()))))

    # Output to Excel
    dfvulnsbytitle2.drop_duplicates().reset_index(drop=True).to_excel(writer2, sheet_name='ConsolidatedByTitle', index=False)


    writer2.save()





# run this script from command line: python 
if len (sys.argv) < 2 :
    print("Usage: "+os.path.basename(__file__) +" azurebenchmarks.csv")

    print("Note: No Trailing slash for fodlers")
    print("Exiting ...")
    sys.exit (1)
elif os.path.isfile(sys.argv[1]):

    inputFile=sys.argv[1]
    print(inputFile, ' is a File')
    #processFile(inputFile)
    mergeconsolidatebytitle(inputFile)

else:
    sys.exit (1)

