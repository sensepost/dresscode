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
data_df=pd.DataFrame()

config=get_config()
collection = get_headers_collection(config)
total_documents = collection.count_documents({})
n_top_header_names = 20 
n_top_directive_names = 15

#### DASH CALLBACKS ###

@callback(
    [Output(component_id='graph-headers-freq',component_property='figure'),
     Output(component_id='graph-csp-directives-freq',component_property='figure')],
    [Input(component_id='store-data', component_property='data'),
    Input(component_id='input-number-top-headers-names',component_property='value'),
    Input(component_id='input-number-top-directive-names',component_property='value'),
     Input(component_id="collection-data",component_property="data")]
)
def reload_all_graphs(stored_data,n_limit_header_names,n_limit_directive_names,collection_data):
    print("collection_data: "+collection_data) 
    config=get_config(collection_data)
    collection = get_headers_collection(config)
    find_limit=stored_data["find_limit"]
    
    print("Names - showing %s documents in graphs" % find_limit)
    data_df = pd.DataFrame(list(collection.find({},{"url":1,"headers":1,"csp":1}).limit(find_limit)))
    print("Data pulled form DB. Shaping it with Pandas")
    # Beautify the "headers" Series
    # Make all the headers lowercase 
    print("Beautifying headers")
    # data_df["headers"] = data_df["headers"].map(lambda x: array_to_dict(x,tolower=True))
    data_df["headers_lower"]=data_df["headers"].map(lambda x: dict((k.lower(), v.lower()) for k,v in x.items()) if x is not None else None)
    # Prepare CSP data to visualise sites and directives, etc. Indicate that all headers have been changed to lowercase
    # print("Parsing CSP headers")
    # csp_cspro=data_df["headers_lower"].map(lambda x: parse_csp(x,lower=True))
    # csp_columns_df=pd.DataFrame(csp_cspro.tolist(),columns=["csp","cspro"])
    # data_df=pd.concat([data_df,csp_columns_df],axis=1)
    
    # data["hsts"]=data["headers"].map(lambda x : parse_hsts(x,lower=True))
    print("Filtering null CSP headers and empty directives")
    csp_data=data_df[data_df["csp"].notnull()]
    # csp_data=csp_data[csp_data["csp"].map(lambda x: "" not in x.keys())]
    # Freeing up some memory
    csp_columns_df=None

    # In case I needed to look at the csp ro stats, here's how I would get them
    # print("Filtering null CSP-RO headers and empty directives")
    # cspro_data=data_df[data_df["cspro"].notnull()]
    # cspro_data=csp_data[csp_data["cspro"].map(lambda x: "" not in x.keys())]

    # List unique header names
    header_names,counts_headers = np.unique(np.hstack(data_df["headers_lower"].map(lambda x: list(x.keys())).values),return_counts=True)
    # List unique csp directive names
    directive_names,counts_directives = np.unique(np.hstack(csp_data["csp"].map(lambda x: list(x.keys())).values),return_counts=True)
    # Calculate percentages 
    percentage_headers=np.array(list(map(lambda x: round(x/len(data_df)*100,2),counts_headers)))
    percentage_directives=np.array(list(map(lambda x: round(x/len(csp_data)*100,2),counts_directives)))

    # Dataframe for headers frecuency
    headers_idx=np.argsort(-counts_headers)
    sorted_header_names=header_names[headers_idx]
    sorted_header_freqs=counts_headers[headers_idx]
    # TODO: Show percentages in the bars. They are calculated correctly, but can't show them in the bar plots 
    sorted_header_percentages=percentage_headers[headers_idx]
    # Concatenate the absolute number of frequency with the percentage
    # sorted_header_combo=list(map(lambda x: "%s (%s%%)" % (x[0],x[1]),list(zip(sorted_header_freqs,sorted_header_percentages))))
    sorted_header_combo=list(map(lambda x: f"{x[0]:n} ({x[1]}%)",list(zip(sorted_header_freqs,sorted_header_percentages))))

    headers_freq_df = pd.DataFrame({
        "Header Name": sorted_header_names,
        "Frequency": sorted_header_freqs
    }).head(n_limit_header_names)
    headers_freq_fig = px.bar(headers_freq_df,
                              y="Header Name",
                              x="Frequency", 
                              text=sorted_header_combo[0:n_limit_header_names], 
                              orientation="h",)
                              # text_auto=True)
    headers_freq_fig.update_layout(title="Frequency of Header values", yaxis=dict(autorange="reversed"))
    headers_freq_fig.update_traces(marker_color='rgb(158,202,225)', marker_line_color='rgb(8,48,107)',
                  marker_line_width=1.5, opacity=0.7)
    
    #################################
    # Dataframe for csp directives frecuency
    directives_idx=np.argsort(-counts_directives)
    sorted_directive_names=directive_names[directives_idx]
    sorted_directive_freqs=counts_directives[directives_idx]
    sorted_directive_percentages=percentage_directives[directives_idx]
    # Concatenate absolute and percentage values
    sorted_directive_combo=list(map(lambda x: f"{x[0]:n} ({x[1]}%)",list(zip(sorted_directive_freqs,sorted_directive_percentages))))

    directive_freq_df = pd.DataFrame({
        "Directive Name": sorted_directive_names,
        "Frequency": sorted_directive_freqs
    }).head(n_limit_directive_names)
    directive_freq_fig = px.bar(directive_freq_df,
                                y="Directive Name",
                                x="Frequency",
                                text=sorted_directive_combo[0:n_limit_directive_names],
                                orientation="h",)
                                # text_auto=True)
    directive_freq_fig.update_layout(title="Frequency of CSP directives",yaxis=dict(autorange="reversed"))
    directive_freq_fig.update_traces(marker_color='rgb(158,202,225)', marker_line_color='rgb(8,48,107)',
                  marker_line_width=1.5, opacity=0.7)
    
    return headers_freq_fig, directive_freq_fig

#### APP LAYOUT ####

layout = html.Div(
    children=[
        html.Hr(),
        
        dcc.Loading(
            id="loading-stuff1",
            children=[
                html.H2("Frequency of CSP Directives"),
                html.Label("Show top: "),
                dcc.Input(id='input-number-top-directive-names', debounce=True, type='number', value=n_top_directive_names, min=1, max=total_documents, step=1),
                dcc.Graph(id="graph-csp-directives-freq",style={'width': '100%', 'height': '90vh'}),
                html.H2("Frequency of Headers"),
                html.Label("Show top: "),
                dcc.Input(id='input-number-top-headers-names', debounce=True, type='number', value=n_top_header_names, min=1, max=total_documents, step=1),
                dcc.Graph(id="graph-headers-freq",style={'width': '100%', 'height': '90vh'})

            ]
        ),
    ]
)
