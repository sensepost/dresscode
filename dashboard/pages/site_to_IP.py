from dash import dash_table,html, dcc, callback, Input, Output, register_page
import pandas as pd
import sys
sys.path.append("..")
from utils.utils import get_config,get_headers_collection,array_to_dict,parse_csp
import plotly.express as px

register_page(__name__)

config=get_config()
collection=get_headers_collection(config=config)

@callback(
    [Output(component_id="datatable-site-to-ip",component_property='data'),
     Output(component_id='datatable-site-to-ip',component_property='columns')],
    [Input(component_id='store-data', component_property='data'),
     Input(component_id="collection-data",component_property="data")]
)
def update_maps(stored_data,collection_data):
    config=get_config(collection_data)
    collection = get_headers_collection(config)

    find_limit=stored_data["find_limit"]

    project={'url': 1, 
             "final_url": 1, 
             "_id":0, 
             "country.iso_code": 1, 
             "continent.name": 1,
             "IPv4":1}
    ip_data=pd.DataFrame(collection.aggregate([{'$limit': find_limit},
                                                { '$match': {"IPv4": {'$exists': 1}}}, 
                                                {'$project': project }]))

    # Data Frame for sites with CSP defined
    ip_data["tld"]=ip_data["url"].map(lambda url: url.split(".")[-1])

    # Due to the restrictions of a DataTable, each cell of the dataframe has to be a int, boolean or a string
    # We get weird errors in the frontend if we don't convert all cells to strings:
    # E.g.: Invalid argument `data[0].vulnerabilities` passed into DataTable with ID "datatable-csp". Expected one of type [string, number, boolean].
    # csp_data["csp"]=csp_data["csp"].map(lambda x: str(x)[0:60])
    ip_data["country"]=ip_data["country"].map(lambda x: x["iso_code"] if type(x)!=float else "Unknown")
    ip_data["continent"]=ip_data["continent"].map(lambda x: x["name"] if type(x)!=float else "Unknown")
    ip_data["IPv4"]=ip_data["IPv4"].map(lambda x: str(x).replace(",","\n").replace('[','').replace(']','').replace("'",'').replace(" ",""))
    columns=[{"name": i.replace("_"," ").capitalize(), "id": i, "deletable": True, "selectable": True} for i in ip_data.columns]

    return ip_data.to_dict("records"),columns


layout = html.Div(children=[
    html.H2(children='Site to IP'),
	html.Br(),
        html.Div(id='site-to-ip-div',children=[
        dcc.Loading(
            children=[
                dash_table.DataTable(id='datatable-site-to-ip',
                                    editable=True,
                                    filter_action="native",
                                    sort_action="native",
                                    sort_mode="multi",
                                    column_selectable="single",
                                    row_selectable="multi",
                                    # row_deletable=True,
                                    selected_columns=[],
                                    selected_rows=[],
                                    page_action="native",
                                    page_current= 0,
                                    page_size= 50,
                                    style_cell={
                                        'whiteSpace': 'pre-line'
                                    }
                                    ),
            ]
        )
    ]),
])
