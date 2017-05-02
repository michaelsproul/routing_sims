// Maximum of a list.
function listMax(list) {
    return list.reduce((x, y) => Math.max(x, y));
}

function renderBasicInfo() {
    let options = {
        title: "Network Sections and Nodes",
        xaxis: { title: "step number" },
        yaxis: { title: "number of sections" },
        yaxis2: {
            title: "number of nodes",
            overlaying: "y",
            side: "right"
        }
    };

    var requests = [
        $.getJSON("num_sections.json"),
        $.getJSON("num_nodes.json"),
        $.getJSON("num_malicious.json")
    ];

    // Wait for all in-flight `getJSON` requests.
    $.when.apply($, requests).done(function() {
        var data = [];
        for (let i = 0; i < arguments.length; i++) {
            data.push(arguments[i][0]);
        }
        data.map((d) => d.type = "scatter");
        Plotly.plot("basicInfo", data, options);
    });
}

function renderSectionSizes() {
    let options = {
        title: "Section Sizes",
        xaxis: { title: "step number" },
        yaxis: { title: "number of nodes" },
    };

    $.getJSON("section_sizes.json").done((data) => {
        data.map((d) => {
            d.mode = "markers";
            d.type = "scattergl";
        });
        Plotly.plot("sectionSizes", data, options);
    });
}

function renderMaliciousSections() {
    let options = {
        title: "Malicious Nodes per Section",
        xaxis: { title: "step number" },
        yaxis: { title: "number of malicious nodes" }
    };
    $.getJSON("section_mal.json").done((data) => {
        data.map((d) => {
            d.mode = "markers";
            d.type = "scattergl"
        });
        Plotly.plot("sectionMal", data, options);
    });
}

function renderMaliciousFraction() {
    let options = {
        title: "Most Malicious Section",
        xaxis: { title: "step number" },
        yaxis: { title: "fraction of malicious nodes in section" }
    };
    var requests = [
        $.getJSON("most_malicious_count.json"),
        $.getJSON("most_malicious_age.json")
    ];
    $.when.apply($, requests).done(function() {
        var data = [];
        for (let i = 0; i < arguments.length; i++) {
            data.push(arguments[i][0]);
        }
        Plotly.plot("mostMalicious", data, options);
    });
}

function renderMaliciousAges() {
    let options = {
        title: "Malicious Node Ages",
        xaxis: { title: "step number" },
        yaxis: { title: "age" }
    };
    $.getJSON("malicious_node_ages.json").done((data) => {
        delete data.yaxis;
        data.type = "histogram2d";
        data.autobinx = false;
        data.autobiny = false;
        data.xbins = {
            start: -0.5,
            end: listMax(data.x),
            size: 1
        };
        data.ybins = {
            start: -0.5,
            end: listMax(data.y),
            size: 1
        };
        data.colorscale = [
            [0, 'rgb(255,255,255)'],
            [0.7, 'rgb(230, 22, 22)'],
            [1, 'rgb(10, 56, 191']
        ];

        Plotly.plot("nodeAges", [data], options);
    });
}

function renderQLearningStats() {
    let options = {
        title: "QLearning State Space Exploration",
        xaxis: { title: "step number" },
        yaxis: { title: "number of states seen" }
    };
    $.getJSON("qlearn_stats.json").done((data) => {
        Plotly.plot("attack", [data], options);
    });
}

function renderCorruptData() {
    let options = {
        title: "Data Compromised",
        xaxis: { title: "step number" },
        yaxis: { title: "estimated fraction (network-wide)" }
    };
    $.getJSON("corrupt_data.json").done((data) => {
        Plotly.plot("corrupt_data", [data], options);
    });
}

function renderDoubleVote() {
    let options = {
        title: "Probability of Double Vote",
        xaxis: { title: "step number" },
        yaxis: { title: "max prob double vote" }
    };
    $.getJSON("double_vote.json").done((data) => {
        Plotly.plot("double_vote", [data], options);
    });
}

$(document).ready(() => {
    renderBasicInfo();
    renderSectionSizes();
    renderMaliciousSections();
    renderMaliciousFraction();
    renderMaliciousAges();
    renderQLearningStats();
    renderCorruptData();
    renderDoubleVote();
});
