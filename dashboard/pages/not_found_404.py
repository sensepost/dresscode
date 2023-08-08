from dash import html
import dash

dash.register_page(__name__)

layout = html.Div(children=[
    html.H1("404 - You didn't say the magic word"),
    html.Img(src='../assets/magicword.gif',id='magicword-img')
])