from dash import html, dcc, register_page,callback
from dash.dependencies import Input,Output,State
import plotly.express as px
import pandas as pd
import numpy as np
import re
import sys
sys.path.append("..")
from utils.utils import *

register_page(__name__,path='/')

########
# MAIN #
########

find_limit=10000
data=pd.DataFrame()

config=get_config(environment="majestic_snapshots")
collection = get_headers_collection(config)

#### DASH CALLBACKS ###


@callback(
    Output(component_id='graph-csp-vs-nocsp',component_property='figure'),
    [Input(component_id='store-data', component_property='data'),
     Input(component_id="collection-data",component_property="data")])
def reload_all_graphs(stored_data,collection_data):

    config=get_config(collection_data)
    collection = get_headers_collection(config)
    # total_documents = collection.count_documents({})
    
    find_limit=stored_data["find_limit"]
    print("Names - showing %s documents in graphs" % find_limit)

    # TODO: Add the csp-ro to the graph
    project = { 
        "_id": 0, 
        "globalRank": "$last_scan.globalRank", 
        "csp_present": { '$switch': { 'branches': [{ "case": { '$eq': [ "$last_scan.csp", None ] }, 'then': 0 } ], "default": 1 } } , 
        "cspro_present": { '$switch': { 'branches': [{ "case": { '$eq': [ "$last_scan.cspro", None ] }, 'then': 0 } ], "default": 1 } } 
        }
    data=pd.DataFrame(collection.aggregate([
        { '$sort': { "scans.globalRank": 1 } }, 
        { '$limit': find_limit }, 
        { '$addFields': { 'last_scan': { '$first': { '$sortArray': { 'input': "$scans", 'sortBy': { 'date': -1 } } } } } }, 
        { '$project': project }
        ]))
    
    # CSP-RO and CSP at the same time
    cspro_and_csp=data.query("cspro_present==1 and csp_present==1").count().csp_present
    # CSP-RO and no CSP 
    cspro_wo_csp=data.query("cspro_present==1 and csp_present==0").count().csp_present
    # CSP and no CSP-RO
    csp_wo_cspro=data.query("cspro_present==0 and csp_present==1").count().csp_present
    # No CSP and no CSP-RO
    no_cspro_csp=data.query("cspro_present==0 and csp_present==0").count().csp_present

    print("n with csp and cspro: %s" % cspro_and_csp)
    print("n with cspro w/o csp: %s" % cspro_wo_csp)
    print("n with csp w/o cspro: %s" % csp_wo_cspro)
    print("n csp and no cspro: %s" % no_cspro_csp)
    print("Limit: %s" % find_limit)

    #########################
    # Dataframe for Pie chart 
    csp_vs_noncsp_df = pd.DataFrame({
        "CSP": ["Report-Only", "Both", "CSP", "None"],
        "Number": [cspro_wo_csp, cspro_and_csp, csp_wo_cspro, no_cspro_csp],
    })

    cspvsnocsp_fig = px.pie(csp_vs_noncsp_df, 
                            names="CSP", 
                            values="Number",
                            title=f"Defining a Content Security Policy in 2023 (sample size: {find_limit: n} sites)",
                            color_discrete_sequence=["#FF7900","green","goldenrod"])
                            # color_discrete_sequence=px.colors.qualitative.Alphabet)
    cspvsnocsp_fig.update_traces(marker_line_width=1.5, opacity=0.75,textinfo="percent+value")

    return cspvsnocsp_fig


def get_comparison_figure():
    # Get a dataframe from the DB of the top 100000 sites sorted by globalRank descending.
    top_100000_df=pd.DataFrame(collection.aggregate([{ '$sort': { "scans.globalRank": 1 } }, { '$limit': 100000 }, { '$addFields': { 'last_scan': { '$first': { '$sortArray': { 'input': "$scans", 'sortBy': { 'date': -1 } } } } } }, { '$project': { "_id": 0, "globalRank": "$last_scan.globalRank", "csp_present": { '$switch': { 'branches': [{ "case": { '$eq': [ "$last_scan.csp", None ] }, 'then': 0 } ], "default": 1 } } , "cspro_present": { '$switch': { 'branches': [{ "case": { '$eq': [ "$last_scan.cspro", None ] }, 'then': 0 } ], "default": 1 } } } }]))
    top_1000_df=top_100000_df[0:1000]
    top_10000_df=top_100000_df[0:10000]

    # CSP-RO and CSP at the same time
    cspro_and_csp1=top_1000_df.query("cspro_present==1 and csp_present==1").count().csp_present
    cspro_and_csp2=top_10000_df.query("cspro_present==1 and csp_present==1").count().csp_present
    cspro_and_csp3=top_100000_df.query("cspro_present==1 and csp_present==1").count().csp_present

    # CSP-RO and no CSP 
    cspro_wo_csp1=top_1000_df.query("cspro_present==1 and csp_present==0").count().csp_present
    cspro_wo_csp2=top_10000_df.query("cspro_present==1 and csp_present==0").count().csp_present
    cspro_wo_csp3=top_100000_df.query("cspro_present==1 and csp_present==0").count().csp_present

    # CSP and no CSP-RO
    csp_wo_cspro1=top_1000_df.query("cspro_present==0 and csp_present==1").count().csp_present
    csp_wo_cspro2=top_10000_df.query("cspro_present==0 and csp_present==1").count().csp_present
    csp_wo_cspro3=top_100000_df.query("cspro_present==0 and csp_present==1").count().csp_present

    # No CSP and no CSP-RO
    no_cspro_csp1=top_1000_df.query("cspro_present==0 and csp_present==0").count().csp_present
    no_cspro_csp2=top_10000_df.query("cspro_present==0 and csp_present==0").count().csp_present
    no_cspro_csp3=top_100000_df.query("cspro_present==0 and csp_present==0").count().csp_present

    # The minus is not an error, look at this as a Venn diagram, where we don't want to count the intersection of two sets
    total_1=(cspro_wo_csp1+csp_wo_cspro1-cspro_and_csp1)+no_cspro_csp1
    total_2=(cspro_wo_csp2+csp_wo_cspro2-cspro_and_csp2)+no_cspro_csp2
    total_3=(cspro_wo_csp3+csp_wo_cspro3-cspro_and_csp3)+no_cspro_csp3

    # with_some_csp1=(cspro_wo_csp1+csp_wo_cspro1-cspro_and_csp1)
    # with_some_csp2=(cspro_wo_csp2+csp_wo_cspro2-cspro_and_csp2)
    # with_some_csp3=(cspro_wo_csp3+csp_wo_cspro3-cspro_and_csp3)

    p_csp_1=round(csp_wo_cspro1/(total_1)*100,1)
    p_csp_2=round(csp_wo_cspro2/(total_2)*100,1)
    p_csp_3=round(csp_wo_cspro3/(total_3)*100,1)

    p_cspro_1=round(cspro_wo_csp1/(total_1)*100,1)
    p_cspro_2=round(cspro_wo_csp2/(total_2)*100,1)
    p_cspro_3=round(cspro_wo_csp3/(total_3)*100,1)

    p_cspro_csp_1=round(cspro_and_csp1/(total_1)*100,1)
    p_cspro_csp_2=round(cspro_and_csp2/(total_2)*100,1)
    p_cspro_csp_3=round(cspro_and_csp3/(total_3)*100,1)

    comparison_df=pd.DataFrame({
            "CSP": [p_csp_1,p_csp_2,p_csp_3],
            "CSP-RO": [p_cspro_1,p_cspro_2,p_cspro_3],
            "Both": [p_cspro_csp_1,p_cspro_csp_2,p_cspro_csp_3]
        },
        index=["Top 1000","Top 10000","Top 100000"])

    comparison_fig = px.bar(comparison_df,
                            x=comparison_df.index,
                            y=comparison_df.columns,
                            barmode="group",
                            text_auto=True,
                            labels={
                                "index": "Top # sites",
                                "value": "Percentage (%)"
                            })
    comparison_fig.update_layout(title="Comparison of CSP usage between the top 1000, 10000, and 100000")
    comparison_fig.update_traces(marker_line_width=1.5, opacity=0.8)

    return comparison_fig

#### APP LAYOUT ####

layout = html.Div(
    children=[
        html.Hr(),
        
        dcc.Loading(
            id="loading-pie",
            children=[
                html.H2("Sites Defining a Content Security Policy"),
                dcc.Graph(id="graph-csp-vs-nocsp",style={'width': '80%', 'height': '80vh'}),
                html.H2("Comparison of top 1000, 10000, and 100000 sites ordered by Rank"),
                dcc.Graph(id="graph-comparison",style={'width': '80%', 'height': '80vh'},figure=get_comparison_figure())
            ]
        ),
    ]
)
