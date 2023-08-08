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

config=get_config()
collection = get_headers_collection(config)
# total_documents = collection.count_documents({})

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
    # n_with_cspro=collection.aggregate([{'$match': {"globalRank": {'$exists': 1}}},{'$sort': {"globalRank": 1}},{'$limit': find_limit},{  '$match': {"vulnerabilities.CSPRO": { '$exists': 1}}}, {'$match': {"vulnerabilities.NOCSP": {'$exists': 1}}} ,{'$count': "n_cspro" }]).next()["n_cspro"]
    # n_with_csp=collection.aggregate([{'$sort': {"globalRank": 1}},{'$limit': find_limit},{ '$match': {"vulnerabilities.NOCSP": { '$exists': 0}}},{'$count': "n_csp" }]).next()["n_csp"]
    # n_wo_csp=collection.aggregate([{'$sort': {"globalRank": 1}},{'$limit': find_limit},{ '$match': {"vulnerabilities.NOCSP": { '$exists': 1}}},{'$count': "n_no_csp"}]).next()["n_no_csp"]
    n_with_cspro=collection.aggregate([{'$sort': {"globalRank": 1}},{'$limit': find_limit},{  '$match': {"vulnerabilities.CSPRO": { '$exists': 1}}}, {'$match': {"vulnerabilities.NOCSP": {'$exists': 1}}} ,{'$count': "n_cspro" }]).next()["n_cspro"]
    n_with_csp=collection.aggregate([{'$sort': {"globalRank": 1}},{'$limit': find_limit},{ '$match': {"vulnerabilities.NOCSP": { '$exists': 0}}},{'$count': "n_csp" }]).next()["n_csp"]
    n_wo_csp=collection.aggregate([{'$sort': {"globalRank": 1}},{'$limit': find_limit},{ '$match': {"vulnerabilities.NOCSP": { '$exists': 1}}},{'$count': "n_no_csp"}]).next()["n_no_csp"]
    print("n with csp: %s" % n_with_csp)
    print("n wo csp: %s" % n_wo_csp)
    print("n ro csp: %s" % n_with_cspro)
    print("Limit: %s" % find_limit)

    #########################
    # Dataframe for Pie chart 
    csp_vs_noncsp_df = pd.DataFrame({
        "CSP": ["Report-Only", "No", "Yes"],
        "Number": [n_with_cspro, n_wo_csp,n_with_csp],
    })

    cspvsnocsp_fig = px.pie(csp_vs_noncsp_df, 
                            names="CSP", 
                            values="Number",
                            title=f"Defining a Content Security Policy in 2023 (sample size: {find_limit: n} sites)",
                            color_discrete_sequence=["#FF7900","green","goldenrod"])
                            # color_discrete_sequence=px.colors.qualitative.Alphabet)
    cspvsnocsp_fig.update_traces(marker_line_width=1.5, opacity=0.75,textinfo="percent+value")

    return cspvsnocsp_fig 

#### APP LAYOUT ####

layout = html.Div(
    children=[
        html.Hr(),
        
        dcc.Loading(
            id="loading-pie",
            children=[
                html.H2("Sites Defining a Content Security Policy"),
                dcc.Graph(id="graph-csp-vs-nocsp",style={'width': '80%', 'height': '80vh'})
            ]
        ),
    ]
)
