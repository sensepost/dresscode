from dash import dash_table,html, dcc, callback, Input, Output, register_page
import pandas as pd
import sys
sys.path.append("..")
from utils.utils import get_config,get_headers_collection,array_to_dict,parse_csp
import plotly.express as px

register_page(__name__)

config=get_config()
collection=get_headers_collection(config=config)

vuln_types={
    "Third Party Abuse": "THIRDPARTYABUSE",
    "No CSP": "NOCSP",
    "Unsafe Inline": "UNSAFEINLINE",
    "Unsafe Eval": "UNSAFEEVAL",
    "Lenient Scheme": "LENIENTSCHEME",
    "CSP Report-Only Only": "CSPRO",
    "No default-src": "DEFAULTSRC",
    "No frame-ancestors": "FRAMEANCESTORS",
    "No report-to": "REPORTTO",
    "No base-uri": "BASEURI",
    "No upgrade-insecure-request": "UPGRIR",
    "No script-src and default-src": "NDSCRIPTSRC",
    "No connect-src and default-src": "NDCONNECTSRC",
    "No frame-src and default-src": "NDFRAMESRC",
    "No child-src and default-src": "NDCHILDSRC",
    "No object-src and default-src": "NDOBJECTSRC",
    "Orphan Domains": "ORPHANDOMAIN"
}

@callback(
    [Output(component_id="datatable-csp",component_property='data'),
     Output(component_id='datatable-csp',component_property='columns')],
    [Input(component_id='store-data', component_property='data'),
     Input(component_id="dropdown-vulnerability", component_property='value'),
     Input(component_id="collection-data",component_property="data")]
)
def update_maps(stored_data,vulnerability_type,collection_data):

    config=get_config(collection_data)
    collection = get_headers_collection(config)

    find_limit=stored_data["find_limit"]
    columns=[]

    # return data,columns

    project={'url': 1, 
             "final_url": 1, 
             "_id":0,
             "country.iso_code": 1, 
             "continent.name": 1,
             "vulnerabilities":1
             }
             # "headers": 1,
             # "csp": 1}
    weakness_csp_df=pd.DataFrame(collection.aggregate([{'$limit': find_limit},
                                                { '$match': {"vulnerabilities.{}".format(vuln_types[vulnerability_type]): {'$exists': 1}}}, 
                                                {'$project': project }]))

    if (len(weakness_csp_df)>0):
        # Data Frame for sites with CSP defined
        weakness_csp_df["tld"]=weakness_csp_df["url"].map(lambda url: url.split(".")[-1])

        # Now, to create one column per vulnerability type an assign true or false depending if it's present or not
        weakness_csp_df["Description"]=weakness_csp_df["vulnerabilities"].map(lambda x: x[vuln_types[vulnerability_type]])
        # Now drop the "vulnerabilities" column, we don't need it
        weakness_csp_df.drop("vulnerabilities",axis=1,inplace=True)
        
        # Due to the restrictions of a DataTable, each cell of the dataframe has to be a int, boolean or a string
        # We get weird errors in the frontend if we don't convert all cells to strings:
        # E.g.: Invalid argument `data[0].vulnerabilities` passed into DataTable with ID "datatable-csp". Expected one of type [string, number, boolean].
        # csp_data["csp"]=csp_data["csp"].map(lambda x: str(x)[0:60])
        # csp_data.drop("csp",inplace=True,axis=1)
        weakness_csp_df["country"]=weakness_csp_df["country"].map(lambda x: x["iso_code"] if type(x)!=float else "Unknown")
        weakness_csp_df["continent"]=weakness_csp_df["continent"].map(lambda x: x["name"] if type(x)!=float else "Unknown")
        columns=[{"name": i.replace("_"," ").capitalize(), "id": i, "deletable": True, "selectable": True} for i in weakness_csp_df.columns]
    else:
        print("Empty dataset")
    

    return weakness_csp_df.to_dict("records"),columns


layout = html.Div(children=[
    html.H2(children='Sites and Bypasses'),
	html.Br(),
        html.Div(id='bypasses-div',children=[
        dcc.Loading(
            children=[
                html.Label("Weakness: "),
                dcc.Dropdown(id="dropdown-vulnerability",
                             options=list(vuln_types.keys()),
                             value="Third Party Abuse"),
                html.Br(),
                dash_table.DataTable(id='datatable-csp',
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
                                    export_format="csv",
                                    style_cell={
                                        "textAlign": 'left'
                                    }
                                    ),
            ]
        )
    ]),
])
