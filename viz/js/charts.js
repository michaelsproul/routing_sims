var options = {
  xaxis: {
    autorange: true
  },
  yaxis: {
    title: "number of sections"
  },
  yaxis2: {
    title: "number of nodes",
    overlaying: "y",
    side: "right"
  },
  margin: {
    t: 0
  }
};

var requests = [
  $.getJSON("num_sections.json"),
  $.getJSON("num_nodes.json"),
  $.getJSON("num_malicious.json")
];

$.when.apply($, requests).done(function() {
  var data = [];
  for (let i = 0; i < arguments.length; i++) {
    data.push(arguments[i][0]);
  }
  data.map((d) => d.type = "scatter");
  Plotly.plot("basicInfo", data, options);
});

$.getJSON("section_sizes.json").done((data) => {
  data.map((d) => { d.mode = "markers"; d.type = "scattergl"; });
  Plotly.plot("sectionSizes", data, {});
}).fail(() => {
  alert("section sizes failed")
});

var sectionMalOpts = {
  yaxis: {
    title: "number of malicious nodes"
  }
};
$.getJSON("section_mal.json").done((data) => {
  data.map((d) => { d.mode = "markers"; d.type = "scattergl" });
  Plotly.plot("sectionMal", data, sectionMalOpts);
});

$.getJSON("most_malicious.json").done((data) => {
  Plotly.plot("mostMalicious", [data], {});
});

function listMax(list) {
  return list.reduce((x, y) => Math.max(x, y));
}

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

  var options = {
    yaxis: {
      title: "age",
    }
  };
  Plotly.plot("nodeAges", [data], options);
});

$.getJSON("qlearn_stats.json").done((data) => {
  Plotly.plot("attack", [data], {});
});

$.getJSON("corrupt_data.json").done((data) => {
  Plotly.plot("corrupt_data", [data], {});
});
