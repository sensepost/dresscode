from dash import Dash, html, dcc
import dash
from dash.dependencies import Input,Output,State
from utils.utils import get_config,get_headers_collection,get_environments
import locale
locale.setlocale(locale.LC_ALL, '')  

########
# MAIN #
########

# Define CSS styles
external_stylesheets = [
    'https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css',
    'https://use.fontawesome.com/releases/v5.7.2/css/all.css'
]

app = Dash(__name__, use_pages=True,external_stylesheets=external_stylesheets)

config=get_config()
collection = get_headers_collection(config)
total_documents = collection.count_documents({})

#############
# CALLBACKS #
#############
@app.callback(
    [Output(component_id='store-data', component_property='data'),
     Output(component_id="label-loading-msg",component_property="children")],
    [Input(component_id='percentage-slider', component_property='value'),
    State(component_id='store-data', component_property='data'),
    Input(component_id="collection-data",component_property="data")]
)
def update_storage(value,stored_data,collection_name):
    # Refuse to show 0% of the data, instead show the 0.1 percent
    print("Using the collection %s" % collection_name)
    # Update the collection we are exploring
    config=get_config(collection_name)
    collection = get_headers_collection(config)
    total_documents = collection.count_documents({})

    if (value==0):
        value=0.1
    find_limit=int((value/100)*total_documents)
    print("Updating dataframe to contain %s documents" % find_limit)
    if (stored_data is None or len(stored_data)==0):
        stored_data={"find_limit": find_limit}
    else:
        stored_data["find_limit"]=find_limit
    loading_msg=f'Loading {find_limit:n} documents from database'
    return stored_data,loading_msg

@app.callback(
    [Output(component_id="collection-data",component_property="data")],
    [Input(component_id="collection-dropdown",component_property="value")]
)
def update_target_collection(collection_name):
    print("Storing the collection name as %s" % collection_name)
    return [collection_name]

#### APP LAYOUT ####

# List the links excluding the 404 page
links = []
for page in dash.page_registry.values():
    if page['path']!='/not-found-404':
        links.append(
            html.Li(className="nav-item",children=[
                dcc.Link(
                    "{}".format(page['name']), 
                    href=page["relative_path"],
                    className="nav-link"
                )
            ]),
        )

app.layout = html.Div(id="main-container",
                      className="container-fluid",
                      children=[
    dcc.Store(id='store-data',data={},storage_type='session'),
    dcc.Store(id='collection-data',data=[],storage_type='session'),
    html.H1(children='Top 1M Headers Census Dashboard',style={'text-align': 'center'}),

    html.Hr(),

    html.Div(
        id="div-percentage",
        children=[
        dcc.Dropdown(
            options=get_environments(),
            value="majestic_snapshots",
            id="collection-dropdown"
        ),
        html.H2("Limit of data to load from database"),
        dcc.Slider(
            min=0,
            max=100,
            step=5,
            value=5,
            marks={i: "%s%%" % i for i in range(0,101,5)},
            id="percentage-slider"
        ),
        html.Label("Loading...",id="label-loading-msg")
        ]),
    
    html.Hr(),
    
    # html.Div( children=links),

    html.Ul(id="navigation-links",
            className="nav nav-pills nav-fill",
            children=links),

	dash.page_container
])

if __name__ == '__main__':
    app.run(debug=False,host="0.0.0.0")