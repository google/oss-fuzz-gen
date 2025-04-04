// TODO AdamKorcz: This is too hacky. It should be handled during code generation.
//$("h1:first").addClass("no-pseudo");
//$("h1:first").css("padding-left", "0px")


$( document ).ready(function() {

  $('.high-level-conclusion').click(function(){
    $(this).toggleClass("collapsed");
    $(this).find(".high-level-extended").toggleClass("open");
  })

  window.onclick = function(event) {
    if (!event.target.matches(['#per-fuzzer-coverage-button'])) {
      var stdCDropdown = document.getElementById("per-fuzzer-coverage-dropdown");
        if(stdCDropdown.classList.contains("show")) {
          stdCDropdown.classList.remove("show");
        }
      }
    }

    createTables();

    // Scroll effect for showing in the menu where you are on the page
    $(".content-section").on('scroll', e => {
      $('.report-title').each(function() {
        if($(this).offset().top - 200 < $(window).scrollTop()) {
          var elemId;
          elemId = $(this).closest("a").attr('id');
          $(".left-sidebar-content-box > div > a").each(function( index ) {
            if($(this).attr("href").replace("#", "")===elemId) {
              if(!$(this).hasClass("activeMenuText")) {
                $(this).addClass("activeMenuText");
              }
            } else {
              if($(this).hasClass("activeMenuText")) {
                $(this).removeClass("activeMenuText");
              }
            }
          })
        };
      });
    });

  // Make report boxes collapsible
  $('.report-title').click(function(){
    $(this).toggleClass("collapsed")
    if($(this).closest(".report-box").find(".collapsible").length!==0){
      $(this).closest(".report-box").find(".collapsible").toggleClass("collapsed");
    }
  });
});

// createTables instantiates the datatables.
// During this process the number of rows is 
// checked, and some elements are left out of
// the datatables. Currently, these decisions
// are implemented:
// 1: Only show pagination, length change
//    dropdown when there are more than 10 rows.
// 2: Only show search field when there are more
//    than 4 rows. (This could potentially be change
//    to specific tables instead where fuzzer names
//    vary)
function createTables() {
  $.each(tableIds, function(index, value) {
    createTable(value);
  });
  populateTableData();
}

function createTable(value) {
  // Get number of rows in this table
  var rowCount = $('#'+value+' tr').length;
  var sortByColumn = $('#'+value).data('sort-by-column');
  var sortOrder = $('#'+value).data('sort-order');
  

  var bPaginate;
  var bLengthChange;
  var bInfo;
  var bFilter;

  /*if(rowCount<6) {
    bFilter = false;
  } else {
    bFilter = true;
  }*/
    bFilter = true;

  if(rowCount<12) {
    bPaginate = false;
    bLengthChange = false;
    bInfo = false;
  } else {      
    bPaginate = true;
    bLengthChange = true;
    bInfo = true;
  }      
    bPaginate = true;
    bLengthChange = true;
    bInfo = true;

  var tableConfig = {'bPaginate': bPaginate,
                      'bLengthChange': bLengthChange,
                      'bInfo': bInfo,
                      'bFilter': bFilter,
                      'pageLength': 10,
                      'autoWidth': false,
                      dom:            "Bfrtip",
                      paging: true, 
                      scrollCollapse: true,
                      buttons:        [ {
                        extend: 'colvis',
                        text: "Columns"
                        },
                        {
                          extend: "pageLength",
                          text: "Rows"
                        }],
                      fixedColumns:   {
                          left: 2
                      }
                    }
  var language = {"lengthMenu": "_MENU_ per page",
                  "searchPlaceholder": "Search table",
                  "search": "_INPUT_"}
  tableConfig.language = language;

  
  tableConfig.order = [[sortByColumn, sortOrder]]

  if(value==="fuzzers_overview_table" || value==="all_functions_overview_table") {
    tableConfig.columns = [
      {data: "Func name"},
      {data: "Functions filename"},
      {data: "Args"},
      {data: "Function call depth"},
      {data: "Reached by Fuzzers"},
      {data: "Fuzzers runtime hit"},
      {data: "Func lines hit %"},
      {data: "I Count"},
      {data: "BB Count"},
      {data: "Cyclomatic complexity"},
      {data: "Functions reached"},
      {data: "Reached by functions"},
      {data: "Accumulated cyclomatic complexity"},
      {data: "Undiscovered complexity"}]
      tableConfig.columnDefs = [
        // By default hide the columns:
        // "Args",
        // Function call depth
        // "Fuzzes runtime hit",
        // "I Count",
        // "BB Count"
        {targets: [2, 3, 5, 7, 8], visible: false}
      ]
  }

  // Fuzzer function hit tables
  if(value in fuzzer_table_data) {
    tableConfig.columns = [
      {data: "Function name"},
      {data: "source code lines"},
      {data: "source lines hit"},
      {data: "percentage hit"}
    ]
  }
  
  // Create the table:
  var table = $('#'+value).dataTable(tableConfig);
}

function populateTableData() {
  populateFuzzersOverviewTable("fuzzers_overview_table");
  populateFuzzersOverviewTable("all_functions_overview_table");
  populateFunctionsHitTable();
}

function populateFunctionsHitTable() {
  // Add rows for "Functions hit" table for each fuzzer
  for (const [key, value] of Object.entries(fuzzer_table_data)) {
    var table = $('#'+key).DataTable();
    table.rows.add(fuzzer_table_data[key]);
  }
  table.draw();
}
function populateFuzzersOverviewTable(value) {
  console.log(value)
  var table = $('#'+value).DataTable();
  var dataSet;
  var dataWithMarkup;
  dataWithMarkup = [];

  if(value==="fuzzers_overview_table") {
    for(var i=0;i<all_functions_table_data.length;i++) {
      dataWithMarkup.push(all_functions_table_data[i]);

      // Add styling to percentages
      var wrapper = getPercentageWrapper(dataWithMarkup[i]["Func lines hit %"]);
      dataWithMarkup[i]["Func lines hit %"] = wrapper;
    }
    dataSet = all_functions_table_data;

  }else if(value==="all_functions_overview_table") {
    for(var i=0;i<analysis_1_data.length;i++) {
      dataWithMarkup.push(analysis_1_data[i]);

      // Add styling to percentages
      var wrapper = getPercentageWrapper(dataWithMarkup[i]["Func lines hit %"]);
      dataWithMarkup[i]["Func lines hit %"] = wrapper;
    }
    dataSet = dataWithMarkup;
  }
  table.rows.add(dataSet);
  table.draw();  
}

function getPercentageWrapper(val) {
  var numberString = val.replace('%','');
  var numberFloat = parseFloat(numberString);
  var className = getClassName(numberFloat);
   return `<span class='${className} percentage-wrapper'>${numberString}%</span>`

}

function getClassName(val) {
  if(val<10) {
    return "p0-10"
  }else if(val>10 && val<=20) {
    return "p10-20"
  }else if(val>20 && val<=30) {
    return "p20-30"
  }else if (val>30 && val<=40) {
    return "p30-40"
  }else if (val>40 && val<=50) {
    return "p40-50"
  }else if (val>50 && val<=60) {
    return "p50-60"
  }else if (val>60 && val<=70) {
    return "p60-70"
  } else if (val>70) {
    return "p70-100"
  }

}

function displayCollapseByName() {
  document.getElementById("per-fuzzer-coverage-dropdown").classList.toggle("show");
}


