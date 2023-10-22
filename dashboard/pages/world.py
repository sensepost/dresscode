from dash import html, dcc, callback, Input, Output, register_page
from urllib.request import urlopen
import json
import pandas as pd
import sys
sys.path.append("..")
from utils.utils import get_config,get_headers_collection
import plotly.express as px

register_page(__name__)

wold=None
with open('data/countries.geojson',"r") as f:
    world = json.load(f)

config=get_config(environment="majestic_snapshots")
collection=get_headers_collection(config=config)

@callback(
    [Output(component_id="world-csp-census-percentage",component_property='figure'),
     Output(component_id="world-csp-census-mean",component_property='figure'),
     Output(component_id="continent-csp-violin",component_property='figure'),
     Output(component_id="vulnerability-counter",component_property='figure')],
    [Input(component_id='store-data', component_property='data'),
     Input(component_id="collection-data",component_property="data")]
)
def update_maps(stored_data,collection_data):
    config=get_config(collection_data)
    collection = get_headers_collection(config)

    find_limit=stored_data["find_limit"]

    project = {'url': 1, 
               "_id":0, 
               "country": "$country.iso_code", 
               "continent": "$continent.name",
               "last_scan": "$last_scan",
               "csp": {'$ifNull': [ "$last_scan.csp", {} ] }, 
               "cspro": {'$ifNull': [ "$last_scan.cspro", {} ] },
               "weaknesses": {'$ifNull': [ "$last_scan.weaknesses", {} ] }
               }
    cursor=collection.aggregate([
        { '$sort': { "scans.globalRank": 1 } },
        {'$limit': find_limit},
        {'$addFields': {'last_scan': { '$first': { '$sortArray': { 'input': "$scans", 'sortBy': { 'date': -1 } } } } } },
        {'$project': project },
        {'$addFields': { 
            "size_csp": {'$size': {'$objectToArray': "$csp"}}, 
            "size_cspro": {'$size': {'$objectToArray': "$cspro"}}, 
            "n_vulns": {'$size': {'$objectToArray': "$weaknesses"}}
            }
        }])

    # Data Frame for sites without CSP defined
    data_df = pd.DataFrame(list(cursor))
    data_df["tld"]=data_df["url"].map(lambda url: url.split(".")[-1])
    csp_df=data_df.query("size_csp>0")
    nocsp_df=data_df.query("size_csp==0")

    # Save some memory by removing the "last_scan" column from the dataframe
    data_df.drop(columns="last_scan")
    
    # Group the pd by country and count the number of vulnerabilities
    # Counts
    nocsp_country_n_vulns=dict(nocsp_df.groupby("country").n_vulns.sum())
    nocsp_country_n_sites=dict(nocsp_df.groupby("country").n_vulns.count())
    # There is a bug where "US" also appears as the ISO-3 code of "USA", fix that here:
    if ("US" in nocsp_country_n_vulns.keys()):
        nocsp_country_n_vulns["USA"]=nocsp_country_n_vulns["USA"]+nocsp_country_n_vulns.pop("US")
    if ("US" in nocsp_country_n_sites.keys()):
        nocsp_country_n_sites["USA"]=nocsp_country_n_sites["USA"]+nocsp_country_n_sites.pop("US")

    # Now with csp_df
    # Counts
    csp_country_n_vulns=dict(csp_df.groupby("country").n_vulns.sum())
    csp_country_n_vulns_mean=csp_df.groupby("country").n_vulns.mean()
    csp_country_n_sites=dict(csp_df.groupby("country").n_vulns.count())
    if ("US" in csp_country_n_vulns.keys()):
        csp_country_n_vulns["USA"]=csp_country_n_vulns["USA"]+csp_country_n_vulns.pop("US")
    if ("US" in csp_country_n_sites.keys()):
        csp_country_n_sites["USA"]=csp_country_n_sites["USA"]+csp_country_n_sites.pop("US")

    # Calculate the percentage of sites using CSP per country
    percentages={}
    for nocsp_k,nocsp_v in nocsp_country_n_sites.items():
        if (nocsp_k in csp_country_n_sites.keys()):
            p = round((csp_country_n_sites[nocsp_k]/(csp_country_n_sites[nocsp_k]+nocsp_v))*100,2)
            percentages[nocsp_k]=p

    percentages_df=pd.DataFrame.from_dict(data={"percent": percentages})

    # Percentage of sites without CSP per country
    percent_nocsp_fig = px.choropleth(percentages_df, geojson=world, featureidkey="properties.ISO_A3", 
                        locations=percentages_df.index, 
                        locationmode='ISO-3',
                        color='percent',
                        color_continuous_scale="greens",
                        range_color=(0,max(percentages.values())+5),
                        labels={'percent':'% no CSP'}
                        )
    percent_nocsp_fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})

    # Average vulnerabilities per country
    mean_vulns_fig = px.choropleth(csp_country_n_vulns_mean, geojson=world, featureidkey="properties.ISO_A3", 
                        locations=csp_country_n_vulns_mean.index, 
                        locationmode='ISO-3',
                        color='n_vulns',
                        color_continuous_scale="reds",
                        range_color=(0,csp_country_n_vulns_mean.max()),
                        labels={'n_vulns':'Avg. # Vulns.'}
                        )
    mean_vulns_fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})

    # Now, violin plots
    # Group the vulnerabilities per country
    # csp_country_df["continent_name"]=csp_country_df["continent"].map(lambda x: x["name"])
    csp_country_filtered_df=csp_df.query("continent!='Unknown'") # [csp_country_df["continent_name"]!="Unknown"]
    violin_fig = px.violin(csp_country_filtered_df, 
                           y="n_vulns",
                           x="continent", 
                           box=True,
                           color="continent",
                           color_discrete_sequence=px.colors.qualitative.G10,
                           labels={
                                "continent": "Continent",
                                "n_vulns": "Number of vulnerabilities"
                            })

    # Let's count the most popular vulnerabilities
    vulns_counter = {}
    def count_vulns(vc:dict,vulns:dict):
        if (vulns is not None):
            for k,v in vulns.items():
                if (k not in vc.keys()):
                    vc[k]=1
                else:
                    vc[k]+=1

    csp_df["weaknesses"].map(lambda x: count_vulns(vulns_counter,x))
    vc_df = pd.DataFrame.from_dict(data={"Total": vulns_counter})
    vc_df.sort_values("Total",ascending=False,inplace=True)

    vc_fig = px.bar(vc_df,
                    y=vc_df.index,
                    x="Total",
                    # text=list(vc_df.values),
                    text_auto=True,
                    orientation="h")
    vc_fig.update_layout(yaxis=dict(autorange="reversed"))
    vc_fig.update_traces(marker_color='rgb(158,202,225)', marker_line_color='rgb(8,48,107)',
                  marker_line_width=1.5, opacity=0.7)
    
    return percent_nocsp_fig,mean_vulns_fig,violin_fig,vc_fig


layout = html.Div(children=[
    html.H1(children='The CSP Census Wold Map'),
	html.Br(),
    html.Div(id='maps-div',children=[
        dcc.Loading(
            children=[
                html.H1("Percentage of sites using CSP per country"),
                dcc.Graph(id='world-csp-census-percentage',style={'width': '100%', 'height': '80vh'}),
                html.H1("Mean number of vulnerabilities per country"),
                dcc.Graph(id='world-csp-census-mean',style={'width': '100%', 'height': '80vh'}),
                html.H1("Distribution of CSP Vulnerabilities by Continent"),
                dcc.Graph(id='continent-csp-violin',style={'width': '100%', 'height': '80vh'}),
                html.H1("Vulnerability Frequency"),
                dcc.Graph(id='vulnerability-counter',style={'width': '100%', 'height': '80vh'})
            ]
        )
    ]),
])
