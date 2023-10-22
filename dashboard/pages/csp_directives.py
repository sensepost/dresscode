from dash import html, dcc, register_page,callback
from dash.dependencies import Input,Output,State
import plotly.express as px
import pandas as pd
import numpy as np
import re
import sys
sys.path.append("..")
from utils.utils import *

register_page(__name__)

########
# MAIN #
########

find_limit=10000
data=pd.DataFrame()

config=get_config(environment="majestic_snapshots")
collection = get_headers_collection(config)
total_documents = collection.count_documents({})
n_top_directive_values = 15
n_top_header_values = 15

#### DASH CALLBACKS ###

@callback(
    [Output(component_id="directives-div",component_property="style"),
     Output(component_id="headers-div",component_property="style")],
    [Input(component_id='headers-dropdown', component_property='value')])
def show_hide_element(value):
    dir_style={'display':'none'}
    hdrp_style={'display':'block'}
    if value.lower() == 'content-security-policy':
        dir_style={'display': 'block'}
        hdrp_style={'display': 'none'}

    return dir_style,hdrp_style

@callback(
    [Output(component_id='graph-header-values-freq',component_property='figure'),
     Output(component_id='graph-csp-directive-values-freq',component_property='figure'),
     Output(component_id='headers-dropdown', component_property='options'),
     Output(component_id="directives-dropdown",component_property="options")],
    [Input(component_id='store-data', component_property='data'),
    Input(component_id='headers-dropdown',component_property='value'),
    Input(component_id='directives-dropdown',component_property='value'),
    Input(component_id='input-number-top-directives',component_property='value'),
    Input(component_id='input-number-top-headers',component_property='value'),
     Input(component_id="collection-data",component_property="data")]
)
def reload_all_graphs(stored_data,selected_header,selected_directive,n_limit_directives,n_limit_headers,collection_data):
    print("CSP - Directives showing collection: "+collection_data)
    config=get_config(collection_data)
    collection = get_headers_collection(config)

    print("n_headers: %s" % n_limit_headers) 
    print("n_directives: %s" % n_limit_directives)

    find_limit=stored_data["find_limit"]
    print("Values - showing %s documents in graphs" % find_limit)
    # data = pd.DataFrame(list(collection.aggregate([{'$limit': find_limit},{'$match': {'headers.{}'.format(selected_header) : {'$exists': 1}}},{'$project': {"url":1, "headers":1 }}])))
    data_df = pd.DataFrame(list(collection.aggregate([
        { '$sort': { "scans.globalRank": 1 } },
        { '$limit': find_limit }, 
        { '$addFields': { 'last_scan': { '$first': { '$sortArray': { 'input': "$scans", 'sortBy': { 'date': -1 } } } } } }, 
        { '$addFields': { 'headers_kv': { '$objectToArray': "$last_scan.headers" }, "csp_kv": {'$objectToArray': "$last_scan.csp"} } },
        { '$match': { 
            "headers_kv.k": { '$regex': '^{}$'.format(selected_header), '$options': "i" }, 
            "csp_kv.k": {'$regex': "^{}$".format(selected_directive), '$options': "i" } 
            } 
        }, 
        {'$project': {"url": 1, "headers": "$last_scan.headers", "csp": "$last_scan.csp" }}])))

    # Beautify the "headers" Series
    # data_df["headers"] = data_df["headers"].map(lambda x: array_to_dict(x,tolower=True))
    data_df["headers_lower"]=data_df["headers"].map(lambda x: dict((k.lower(), v.lower()) for k,v in x.items()) if x is not None else {})
    # Prepare CSP data to visualise sites and directives, etc
    # csp_cspro=data_df["headers_lower"].map(lambda x: parse_csp(x,lower=True))
    # csp_columns_df=pd.DataFrame(csp_cspro.tolist(),columns=["csp","cspro"])
    # data_df=pd.concat([data_df,csp_columns_df],axis=1)
    
    # data["hsts"]=data["headers"].map(lambda x : parse_hsts(x,lower=True))
    print("Filtering null CSP headers and empty directives")
    csp_data=data_df[data_df["csp"].notnull()]
    # csp_data=csp_data[csp_data["csp"].map(lambda x: "" not in x.keys())]
    # Freeing up some memory
    # csp_columns_df=None

    # List unique header names
    header_names,counts_headers = np.unique(np.hstack(data_df["headers_lower"].map(lambda x: list(x.keys())).values),return_counts=True)
    # List unique csp directive names
    directive_names,counts_directives = np.unique(np.hstack(csp_data["csp"].map(lambda x: list(x.keys())).values),return_counts=True)

    # Sorting headers and directives frecuency names
    headers_idx=np.argsort(-counts_headers)
    sorted_header_names=header_names[headers_idx]
    
    directives_idx=np.argsort(-counts_directives)
    sorted_directive_names=directive_names[directives_idx]

    ################################
    # update the headers values frequency graph
    selected_headers_data=data_df[data_df["headers_lower"].map(lambda x: selected_header in x.keys())]
    header_values,counts_header_values=np.unique(np.hstack(selected_headers_data["headers_lower"].map(lambda x: x[selected_header])),return_counts=True)
    header_vals_idx=np.argsort(-counts_header_values)
    sorted_header_vals_names=header_values[header_vals_idx]
    sorted_header_vals_counts=counts_header_values[header_vals_idx]
    dir_vals_freq_df=pd.DataFrame({
        "Value": sorted_header_vals_names,
        "Count": sorted_header_vals_counts
    }).head(n_limit_headers)
    header_vals_freq_fig = px.bar(dir_vals_freq_df,y="Value",x="Count",orientation="h",text_auto=True)
    header_vals_freq_fig.update_layout(yaxis=dict(autorange="reversed"))
    header_vals_freq_fig.update_traces(marker_color='rgb(158,202,225)', marker_line_color='rgb(8,48,107)',
                  marker_line_width=1.5, opacity=0.7)

    #################################
    # Update the directives values frequency graph
        # If the trigger was the input of number of top values
    # print("Updating the graph to show values of the csp header %s and show the %s top" % (selected_directive,n_limit_directives))
    # Filter only the elements that contain the target directive name
    # Pull the data from DB
    # csp_data = pd.DataFrame(list(collection.find({"headers.Content-Security-Policy": {"$exists": True}}).limit(find_limit)))
    # csp_data["headers"]=csp_data["headers"].map(array_to_dict)
    # csp_data["csp"]=csp_data["headers"].map(parse_csp)
    csp_data=data_df[data_df["csp"].notnull()]
    csp_data_w_directive=csp_data[csp_data["csp"].map(lambda x: selected_directive in x.keys())]
    # Show the elements configured for this directive
    directive_values,counts_directive_values=np.unique(np.hstack(csp_data_w_directive["csp"].map(lambda x: x[selected_directive])),return_counts=True)
    directive_vals_idx=np.argsort(-counts_directive_values)
    sorted_directive_vals_names=directive_values[directive_vals_idx]
    sorted_directive_vals_counts=counts_directive_values[directive_vals_idx]
    dir_vals_freq_df=pd.DataFrame({
        "Value": sorted_directive_vals_names,
        "Count": sorted_directive_vals_counts
    }).head(n_limit_directives)
    
    dir_vals_freq_fig = px.bar(dir_vals_freq_df,y="Value",x="Count",orientation="h",text_auto=True)
    dir_vals_freq_fig.update_layout(yaxis=dict(autorange="reversed"))
    dir_vals_freq_fig.update_traces(marker_color='rgb(158,202,225)', marker_line_color='rgb(8,48,107)',
                  marker_line_width=1.5, opacity=0.7)

    # print("Returning the following directive_names: %s" % sorted_directive_names)

    return header_vals_freq_fig, dir_vals_freq_fig, sorted_header_names, sorted_directive_names

#### APP LAYOUT ####

layout = html.Div(
    children=[
        html.Div( 
            id="div-exploration-controls",
            children=[
                html.H2("Header Values To Visualise"),
                html.Table(
                    style={'width': '100%', 'border': "1px solid black"},
                    id="table-headers-values-controls",
                    children=[
                        html.Tr(
                            children=[
                                html.Td(
                                    children=[
                                        html.Label("Header: ")
                                    ]
                                ),
                                html.Td(
                                    children=[
                                        dcc.Dropdown(
                                            options=["content-security-policy"],
                                            value="content-security-policy",
                                            id="headers-dropdown",
                                            style={"display": "block"}
                                        )
                                    ]
                                ),
                             ]),
                            html.Tr(children=[
                                html.Td(
                                    children=[
                                        html.Label("Show top: ")
                                    ]
                                ),
                                html.Td(
                                    children=[
                                        dcc.Input(id='input-number-top-headers', debounce=True, type='number', value=n_top_header_values, min=1, max=total_documents, step=1)
                                    ]
                                )
                            ]
                        )
                    ]
                ),
            ]
        ),

        # To show the headers values graph
        html.Div(
            id="headers-div",
            children=[
                dcc.Loading(
                    id="loading-header",
                    children=[
                        dcc.Graph(id="graph-header-values-freq",style={'width': '100%', 'height': '90vh'})
                    ]
                )
            ]
        ),
        
        html.Div(
        id="directives-div",
        children=[
            html.H2("CSP directive to visualise"),
            html.Table(
                style={'width': '100%', 'border': "1px solid black"},
                id="table-controls-csp-directives",
                children=[
                    html.Tr(children=[
                        html.Td(children=[
                            html.Label("Directive: ")
                        ]),
                        html.Td(children=[
                            dcc.Dropdown(
                                options=["script-src"],
                                value="script-src",
                                id="directives-dropdown",
                            ),               
                        ]),
                    ]),
                    html.Tr(children=[
                        html.Td(
                            children=[
                                html.Label("Show top: ")
                            ]
                        ),
                        html.Td(children=[
                            dcc.Input(id='input-number-top-directives', type='number', debounce=True, value=n_top_directive_values, min=1, max=total_documents, step=1),
                        ])
                    ])
                ]
            ),
            dcc.Loading(
                id="loading-csp-directives",
                children=[
                    dcc.Graph(id="graph-csp-directive-values-freq",style={'width': '100%', 'height': '90vh'})
                ])
        ],
        style={'display':'block','width' : '50%'}),
    ]
)