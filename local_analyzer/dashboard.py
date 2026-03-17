import dash
from dash import html, dcc, Input, Output
import plotly.express as px
import plotly.graph_objects as go
from data_fetcher import load_data
from analytics import device_summary, compute_best_device, compute_percentage_difference
from datetime import datetime
import pandas as pd
from report_logic import interpret_latency, interpret_throughput, interpret_variance

# ── Data ─────────────────────────────────────────────────────────────
df = load_data()
LAST_UPDATED = datetime.now().strftime("%d %b %Y, %H:%M")

# ── Theme ─────────────────────────────────────────────────────────────
COLORS = {
    "bg":        "#f0f4f8",
    "card":      "#ffffff",
    "border":    "#dce6f0",
    "accent":    "#4a90b8",
    "accent2":   "#6db3d4",
    "text":      "#2c3e50",
    "muted":     "#7f95a8",
    "badge_bg":  "#e6f0f8",
    "badge_txt": "#3a7ca5",
}

PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="#f7fafd",
    font=dict(family="'DM Sans', sans-serif", color=COLORS["text"], size=13),
    margin=dict(l=20, r=20, t=48, b=20),
    title_font=dict(size=15, color=COLORS["text"]),
    colorway=["#4a90b8", "#6db3d4", "#a0cfe0", "#c5dfec", "#83b4cc"],
    xaxis=dict(gridcolor=COLORS["border"], linecolor=COLORS["border"], showgrid=True),
    yaxis=dict(gridcolor=COLORS["border"], linecolor=COLORS["border"], showgrid=True),
    legend=dict(
        bgcolor="rgba(255,255,255,0.7)",
        bordercolor=COLORS["border"],
        borderwidth=1,
        font=dict(size=12),
    ),
)

def apply_theme(fig):
    fig.update_layout(**PLOT_LAYOUT)
    return fig

# ── Helpers ───────────────────────────────────────────────────────────
def card(children, extra_style=None):
    style = {
        "background": COLORS["card"],
        "border": f"1px solid {COLORS['border']}",
        "borderRadius": "12px",
        "padding": "24px",
        "boxShadow": "0 2px 8px rgba(74,144,184,0.07)",
        "marginBottom": "20px",
    }
    if extra_style:
        style.update(extra_style)
    return html.Div(children, style=style)

def section_title(text):
    return html.H2(text, style={
        "fontSize": "13px",
        "fontWeight": "600",
        "letterSpacing": "0.08em",
        "textTransform": "uppercase",
        "color": COLORS["muted"],
        "marginBottom": "16px",
        "marginTop": "0",
    })

def stat_block(label, value, icon=""):
    return html.Div([
        html.Div(f"{icon} {label}" if icon else label, style={
            "fontSize": "12px",
            "color": COLORS["muted"],
            "fontWeight": "500",
            "marginBottom": "6px",
            "letterSpacing": "0.05em",
            "textTransform": "uppercase",
        }),
        html.Div(str(value), style={
            "fontSize": "28px",
            "fontWeight": "700",
            "color": COLORS["text"],
            "letterSpacing": "-0.02em",
        }),
    ], style={"flex": "1", "minWidth": "120px"})

def badge(text, color=None):
    return html.Span(text, style={
        "background": COLORS["badge_bg"],
        "color": color or COLORS["badge_txt"],
        "borderRadius": "6px",
        "padding": "3px 10px",
        "fontSize": "13px",
        "fontWeight": "600",
        "display": "inline-block",
    })

def interpretation_row(label, text):
    return html.Div([
        html.Span(label + ": ", style={
            "fontWeight": "600",
            "color": COLORS["accent"],
            "marginRight": "6px",
            "fontSize": "14px",
        }),
        html.Span(text, style={"color": COLORS["text"], "fontSize": "14px"}),
    ], style={"marginBottom": "10px"})

# ── App ───────────────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[
        "https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap"
    ]
)
server = app.server

PAGE_STYLE = {
    "fontFamily": "'DM Sans', sans-serif",
    "background": COLORS["bg"],
    "minHeight": "100vh",
    "padding": "32px 40px",
    "color": COLORS["text"],
    "boxSizing": "border-box",
}

GRAPH_CONFIG = {"displayModeBar": False}

# ── Empty state ───────────────────────────────────────────────────────
if df.empty:
    app.layout = html.Div([
        html.Div([
            html.H2("No Data Available", style={"color": COLORS["text"], "marginBottom": "8px"}),
            html.P("Check MongoDB connection or run client first.", style={"color": COLORS["muted"]}),
        ], style={
            "background": COLORS["card"],
            "border": f"1px solid {COLORS['border']}",
            "borderRadius": "12px",
            "padding": "48px",
            "textAlign": "center",
            "maxWidth": "420px",
            "margin": "80px auto",
        })
    ], style=PAGE_STYLE)

else:
    # ── Summary ───────────────────────────────────────────────────────
    summary = device_summary(df)
    summary = compute_percentage_difference(summary)
    best = compute_best_device(summary)
    s = summary.reset_index()

    total_clients = df["device_ip"].nunique()
    total_tests = len(df)

    # ── Graphs ────────────────────────────────────────────────────────
    latency_fig = apply_theme(px.line(
        df, x="timestamp", y="latency_ms",
        color="device_name",
        title="Latency Over Time"
    ))

    throughput_fig = apply_theme(px.line(
        df, x="timestamp", y="throughput_Mbps",
        color="device_name",
        title="Throughput Over Time"
    ))

    handshake_fig = apply_theme(px.bar(
        s, x="device_name", y="avg_handshake",
        title="Avg TCP Handshake Time"
    ))

    throughput_bar = apply_theme(px.bar(
        s, x="device_name", y="avg_throughput",
        title="Avg Throughput"
    ))

    stability_fig = apply_theme(px.bar(
        s, x="device_name", y="stability",
        title="Connection Stability"
    ))

    # ── Interpretation ────────────────────────────────────────────────
    latency_text = interpret_latency(s["avg_latency"].mean())
    throughput_text = interpret_throughput(s["avg_throughput"].mean())
    variance_text = interpret_variance(s["stability"].mean())

    # ── Layout ────────────────────────────────────────────────────────
    app.layout = html.Div([

        # Header
        html.Div([
            html.Div([
                html.H1("Network Performance Analyzer", style={
                    "margin": "0 0 4px 0",
                    "fontSize": "24px",
                    "fontWeight": "700",
                    "color": COLORS["text"],
                    "letterSpacing": "-0.02em",
                }),
                html.Span(f"Last updated: {LAST_UPDATED}", style={
                    "fontSize": "12px",
                    "color": COLORS["muted"],
                }),
            ]),
        ], style={"marginBottom": "28px"}),

        # Stats row
        card(
            html.Div([
                stat_block("Total Clients", total_clients, "🖥"),
                stat_block("Total Tests", total_tests, "📡"),
                html.Div(style={"flex": "2"}),  # spacer
            ], style={"display": "flex", "gap": "40px", "flexWrap": "wrap"}),
        ),

        # Best Devices
        card([
            section_title("Best Devices"),
            html.Div([
                html.Div([
                    html.Div("Best Latency", style={"fontSize": "12px", "color": COLORS["muted"], "marginBottom": "4px"}),
                    badge(best["best_latency"]),
                ], style={"flex": "1"}),
                html.Div([
                    html.Div("Best Throughput", style={"fontSize": "12px", "color": COLORS["muted"], "marginBottom": "4px"}),
                    badge(best["best_throughput"]),
                ], style={"flex": "1"}),
                html.Div([
                    html.Div("Most Stable", style={"fontSize": "12px", "color": COLORS["muted"], "marginBottom": "4px"}),
                    badge(best["most_stable"]),
                ], style={"flex": "1"}),
            ], style={"display": "flex", "gap": "24px", "flexWrap": "wrap"}),
        ]),

        # Interpretation
        card([
            section_title("Interpretation"),
            interpretation_row("Latency", latency_text),
            interpretation_row("Throughput", throughput_text),
            interpretation_row("Stability", variance_text),
        ]),

        # Line graphs side by side
        html.Div([
            html.Div(
                card([dcc.Graph(figure=latency_fig, config=GRAPH_CONFIG)],
                     extra_style={"marginBottom": "0"}),
                style={"flex": "1"}
            ),
            html.Div(
                card([dcc.Graph(figure=throughput_fig, config=GRAPH_CONFIG)],
                     extra_style={"marginBottom": "0"}),
                style={"flex": "1"}
            ),
        ], style={"display": "flex", "gap": "20px", "marginBottom": "20px"}),

        # Bar graphs row
        html.Div([
            html.Div(
                card([dcc.Graph(figure=handshake_fig, config=GRAPH_CONFIG)],
                     extra_style={"marginBottom": "0"}),
                style={"flex": "1"}
            ),
            html.Div(
                card([dcc.Graph(figure=throughput_bar, config=GRAPH_CONFIG)],
                     extra_style={"marginBottom": "0"}),
                style={"flex": "1"}
            ),
            html.Div(
                card([dcc.Graph(figure=stability_fig, config=GRAPH_CONFIG)],
                     extra_style={"marginBottom": "0"}),
                style={"flex": "1"}
            ),
        ], style={"display": "flex", "gap": "20px", "marginBottom": "20px"}),

        # Summary Table
        card([
            section_title("Summary Table"),
            html.Div(
                html.Table([
                    html.Thead(
                        html.Tr([
                            html.Th(col, style={
                                "padding": "10px 16px",
                                "textAlign": "left",
                                "fontSize": "12px",
                                "fontWeight": "600",
                                "color": COLORS["muted"],
                                "letterSpacing": "0.05em",
                                "textTransform": "uppercase",
                                "borderBottom": f"2px solid {COLORS['border']}",
                                "whiteSpace": "nowrap",
                            }) for col in s.columns
                        ])
                    ),
                    html.Tbody([
                        html.Tr(
                            [
                                html.Td(s.iloc[i][col], style={
                                    "padding": "10px 16px",
                                    "fontSize": "13px",
                                    "color": COLORS["text"],
                                    "borderBottom": f"1px solid {COLORS['border']}",
                                    "whiteSpace": "nowrap",
                                }) for col in s.columns
                            ],
                            style={
                                "background": COLORS["card"] if i % 2 == 0 else COLORS["bg"],
                            }
                        ) for i in range(len(s))
                    ])
                ], style={"width": "100%", "borderCollapse": "collapse"}),
                style={"overflowX": "auto"}
            ),
        ]),

        # Footer
        html.Div(
            f"Network Performance Analyzer · {LAST_UPDATED}",
            style={
                "textAlign": "center",
                "fontSize": "12px",
                "color": COLORS["muted"],
                "padding": "16px 0 8px",
            }
        ),

    ], style=PAGE_STYLE)

# ── Run ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)