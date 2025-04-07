var StdCFuncNames;
StdCFuncNames = ["free", "abort", "malloc", "calloc", "exit", "memcmp", "strlen"];


$( document ).ready(function() {
    $('.coverage-line-inner').click(function(){
      var wrapper = $(this).closest(".calltree-line-wrapper");
      var wrapperClasses = $(wrapper).attr("class").split(/\s+/);
      var level;
      for(i=0;i<wrapperClasses.length;i++) {
        if(wrapperClasses[i].includes("level-")) {
          level = parseInt(wrapperClasses[i].split("-")[1]);
        }
      }
      var nextLevel = "level-"+(level+1);
      var childLineWrapper = $(this).closest(".coverage-line").find(".calltree-line-wrapper."+nextLevel);
      if($(childLineWrapper).hasClass("open")) {
        $(childLineWrapper).height($(childLineWrapper).get(0).scrollHeight).height("0px").toggleClass("open");
      } else {
        $(childLineWrapper).height($(childLineWrapper).get(0).scrollHeight).toggleClass("open");
        // If we don't use a timeout here, then the height is changed before the csss transition
        // is executed, and the css transition will not be used. We have to set auto height here,
        // because we nested collapsibles.
        setTimeout(function() {
          $(childLineWrapper).height("auto");
        }, 200);
      }
      if($(this).hasClass("expand-symbol")) {
        $(this).removeClass("expand-symbol");
        $(this).addClass("collapse-symbol");
      }else if($(this).hasClass("collapse-symbol")) {
        $(this).removeClass("collapse-symbol");
        $(this).addClass("expand-symbol");
      }
  });

  // Create nav bar
  createNavBar();

  // Add the expand symbols to all nodes that are expandable
  addExpandSymbols();

  // Add blocker lines to the calltree
  var funcList = addFuzzBlockerLines();

  // Instantiate all click events for buttons in the navbar
  addNavbarClickEffects();

  // Add all collapsible functions to the collapse-by-funcname dropdown.
  // This is done here AFTER the dropdown itself has been created.
  addCollapsibleFunctionsToDropdown(funcList);


  var innerNodes = document.getElementsByClassName("collapse-function-with-name");

  for (var i = 0; i < innerNodes.length; i++) {
    innerNodes[i].addEventListener('click', function(e) {
      e = e || window.event;
      var target = e.target;
      var funcName = target.innerText;

      // Close all nodes with this funcName:
      var elems = document.getElementsByClassName("coverage-line-inner collapse-symbol");
      for(var i=0;i<elems.length;i++) {
        if(elems[i].querySelector(".language-clike").innerText.trim()===funcName) {
          elems[i].click()
        }
      }
    }, false);
  }
  
  tabLineHover();

  addImageOverview();

  // if "scrollToNode" was passed to the URL, scroll:
  // This should be in the last bit to ensure all loading is done beforehand.
  scrollOnLoad();
});

function addImageOverview() {

  let img = document.createElement("img");
  let imageName = document.getElementsByClassName("top-navbar-title")[0].innerText.split("Fuzz introspector: ")[1];
  img.src = sanitizeString(imageName)+"_colormap.png";
  img.style.width = "70vh";
  img.style.position = "sticky";
  img.style.top = "40vh";

  console.log(document.getElementsByClassName("content-wrapper")[0])
  document.getElementById("side-overview-wrapper").prepend(img);
}

function sanitizeString(str){
    str = str.replace(/[^a-z0-9áéíóúñü \.,_-]/gim,"");
    return str.trim();
}

// Scrolls to a node if the "scrollToNode" parameters is given
function scrollOnLoad() {
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  const scrollToNode = urlParams.get('scrollToNode')
  if(scrollToNode!==null) {
    var dataValue = "[data-calltree-idx='"+scrollToNode+"']";
    var elementToScrollTo = document.querySelector(dataValue);
    if(elementToScrollTo===null) {
      return
    }
    elementToScrollTo.style.background = "#ffe08c";
    elementToScrollTo.scrollIntoView({behavior: "smooth", block: "center"})
  }
}

// Scrolls to a node
function scrollToNodeInCT(nodeId) {
  var dataValue = "[data-calltree-idx='"+nodeId+"']";
  var elementToScrollTo = document.querySelector(dataValue);
  if(elementToScrollTo===null) {
    return
  }
  elementToScrollTo.style.background = "#ffe08c";
  elementToScrollTo.scrollIntoView({behavior: "smooth", block: "center"})
}

// Checks whether child is a descendant of parent.
function isDescendant(parent, child) {
  var node = child.parentNode;
  while (node != null) {
    if (node == parent) {
      return true;
    }
    node = node.parentNode;
  }
  return false;
}

// Adds the fuzz blocker lines to the nodes in the calltree
function addFuzzBlockerLines() {
  var coverageLines;
  coverageLines = document.getElementsByClassName("coverage-line-inner");
  var allDataIdx = document.querySelectorAll('[data-foo="value"]');

  var funcList;
  funcList = [];
  var blocker_infos = JSON.parse(fuzz_blocker_infos);
  for(var i=0;i<coverageLines.length;i++) {
    // Add fuzz blocker line
    var thisDataIdx = coverageLines[i].getAttribute("data-calltree-idx");
    if(thisDataIdx!==null && thisDataIdx in blocker_infos) {
      coverageLines[i].classList.add("with-fuzz-blocker-line");
      let infoBtn = document.createElement("a");
      infoBtn.classList.add("fuzz-blocker-info-btn");
      infoBtn.innerText = "FUZZ BLOCKER";
      infoBtn.href = blocker_infos[thisDataIdx];
      coverageLines[i].append(infoBtn);
    }

    // Get data for navbar buttons
    if(coverageLines[i].classList.contains("collapse-symbol")) {
      // Get data for std c func names dropdown
      if(coverageLines[i].querySelector(".language-clike")===undefined) {
        continue
      }
      let funcName = coverageLines[i].querySelector(".language-clike").innerText.trim();
      if(!funcList.includes(funcName)) {
        funcList.push(funcName)
      }
    }

  }
  funcList.sort();
  return funcList;
}

/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */
function displayNavBar() {
  document.getElementById("myDropdown").classList.toggle("show");
}
function displayFontSizeDropdown() {
  document.getElementById("fontSizeDropdown").classList.toggle("show");
}
function displayCollapseByName() {
  document.getElementById("collapseByNameDropdown").classList.toggle("show");
}

function createNavBar() {
  // Create the navbar wrapper element
  let e = createNavbarButtonsWrapper();

  // Add buttons to the navbar
  addBackButton(e)
  addExpandAllBtn(e);
  addCollapseAllBtn(e);
  addStdCDropdown(e);
  addCollapseByNameBtn(e);
  addFontSizeDropdown(e);

  // All buttons have been added. Add the wrapper to the navbar
  addButtonsWrapperToNavbar(e);
}

// Instantiates an empty wrapper for the buttons in the navbar
function createNavbarButtonsWrapper() {
  let e = document.createElement("div");
  e.classList.add("calltree-navbar");
  return e;  
}

// Adds the buttons wrapper element to the navbar
function addButtonsWrapperToNavbar(buttonsWrapper) {
  document.getElementsByClassName("content-wrapper")[0].prepend(buttonsWrapper);
}

// Adds the font size dropdown to "parentElement"
function addFontSizeDropdown(parentElement) {
  parentElement.append(createFontSizeDropdown());
}

// Adds collapsible functions to the dropdown
function addCollapsibleFunctionsToDropdown(funcNames) {
  var collapseByNameDropdown = document.getElementById("collapseByNameDropdown");
  for(var i=0;i<funcNames.length;i++) {
    let listItem = document.createElement("div");
    listItem.classList.add("checkbox-line-wrapper");
    listItem.classList.add("collapse-function-with-name");
    listItem.style.display = "block"
    listItem.innerText = funcNames[i];
    collapseByNameDropdown.append(listItem)
  }
}

function createCollapseByName() {
  let btn4 = document.createElement("span");
  btn4.classList.add("calltree-nav-btn2");
  btn4.id = "collapse-by-name";
  var htmlString = "";
  htmlString += `<div class="dropdown">
    <button onclick="displayCollapseByName()" class="dropbtn collapse-by-name-dropdown">Collapse by name</button>
    <div id="collapseByNameDropdown" class="dropdown-content coll-by-name" style="max-height: 500px; overflow-y: scroll">`          
  htmlString += `</div>
  </div>`;
  btn4.innerHTML = htmlString;
  return btn4;
}

// Adds the back button to the nav bar
function addBackButton(parentElement) {
  let backBtn = document.createElement("a");
  backBtn.style.marginRight = "10px";
  backBtn.style.textDecoration = "none";
  backBtn.href = "fuzz_report.html"
  let backBtnInner = document.createElement("span");
  backBtnInner.classList.add("calltree-nav-btn");
  backBtnInner.innerText = "< Back to report";
  backBtn.prepend(backBtnInner);
  parentElement.prepend(backBtn);
}

// Adds the expand all btn to "parentElement"
function addExpandAllBtn(parentElement) {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn");
  btn.id = "expand-all-button"
  btn.innerText = "Expand all";
  parentElement.append(btn);
}

// Adds the collapse all btn to "parentElement"
function addCollapseAllBtn(parentElement) {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn");
  btn.id = "collapse-all-button"
  btn.innerText = "Collapse all";
  parentElement.append(btn);  
}

// Adds the std c dropdown to "parentElement"
function addStdCDropdown(parentElement) {
  let btn = createStdCDropdown();
  parentElement.append(btn);
}

function createStdCDropdown() {
  let btn4 = document.createElement("span");
  btn4.classList.add("calltree-nav-btn2");
  btn4.id = "std-lib-functions";

  // Create the html
  var dropDownHtml = `<div class="dropdown">
    <button onclick="displayNavBar()" class="dropbtn std-c-func-list">Std C funcs</button>
    <div id="myDropdown" class="dropdown-content stdlibc">`
  
  var funcNames = StdCFuncNames;
  for(var i=0;i<funcNames.length;i++) {
    var funcName = funcNames[i];
    dropDownHtml += `<div style="display:flex" class="checkbox-line-wrapper">
        <div style="flex:1"><input type="checkbox" name="${funcName}-chckbox" id="${funcName}-chckbox" class="shown-checkbox" checked></div>
        <div style="flex:3">${funcName}</div>
      </div>`
  }

  // Close the html
  dropDownHtml += "</div></div>";
  btn4.innerHTML = dropDownHtml;
  return btn4;
}

// Adds the collapse by name button to parentElement
function addCollapseByNameBtn(parentElement) {
  let btn = createCollapseByName();
  parentElement.append(btn);  
}

function addNavbarClickEffects() {
  // std c funcs dropdown
  // Close the dropdown menu if the user clicks outside of it
  window.onclick = function(event) {
    if (!event.target.matches(['.std-c-func-list','.font-size-dropdown', '.collapse-by-name-dropdown'])) {
      var stdCDropdown = document.getElementById("myDropdown");
      if(stdCDropdown.classList.contains("show")) {
        stdCDropdown.classList.remove("show");
      }

      var fontSize = document.getElementById("fontSizeDropdown");
      if(fontSize.classList.contains("show")) {
        fontSize.classList.remove("show");
      }

      var fontSize = document.getElementById("collapseByNameDropdown");
      if(fontSize.classList.contains("show")) {
        fontSize.classList.remove("show");
      }
    } else if(event.target.matches('.std-c-func-list')) {
      hideDropdown("collapseByNameDropdown");
      hideDropdown("fontSizeDropdown");
    } else if(event.target.matches('.font-size-dropdown')) {
      hideDropdown("collapseByNameDropdown");
      hideDropdown("myDropdown");
    } else if(event.target.matches('.collapse-by-name-dropdown')) {
      hideDropdown("fontSizeDropdown");
      hideDropdown("myDropdown");
    }
  }
  // Don't close std c funcs drop down when (un)checking a checkbox:
  document.addEventListener('click', function(e) {
    e = e || window.event;
    var target = e.target;
    var menuElement = document.getElementById("myDropdown");
    if(isDescendant(menuElement, target)) {
       e.stopPropagation();
    }
  }, false);

  // Click click effects for hide/show std c funcs
  createStdCClickeffects();

  $("#expand-all-button").click(function(){
    Array.from(document.querySelectorAll('.calltree-line-wrapper:not(.open)')).forEach((el) => el.classList.add('open'));
    Array.from(document.querySelectorAll('.coverage-line-inner.expand-symbol')).forEach(function(el) {
      el.classList.remove('expand-symbol')
      el.classList.add('collapse-symbol')
    });
  })

  $("#collapse-all-button").click(function(){
    Array.from(document.querySelectorAll('.calltree-line-wrapper.open')).forEach((el) => el.classList.remove('open'));
    Array.from(document.querySelectorAll('.coverage-line-inner.collapse-symbol')).forEach(function(el) {
      el.classList.remove('collapse-symbol')
      el.classList.add('expand-symbol')
    });
  });

  $(".fontsize-option").click(function(){
    var selectedFontSize=$(this).data("fontsize");
    $(".coverage-line-inner").css("font-size", selectedFontSize);
    $(".fontsize-option").removeClass("active");
    $(this).addClass("active");
  })

}

function createStdCClickeffects() {  
  // Add click effects to std c checkboxes
  var funcNames = StdCFuncNames;

  // Create array of the elements
  var elemsArray;
  elemsArray = [];
  for(var i=0;i<funcNames.length;i++) {
    var funcName = funcNames[i];
    var checkboxIdString = funcName+'-chckbox'
    let elem = document.getElementById(checkboxIdString);
    elemsArray.push(elem);
  }

  // Create click effects of the elements
  elemsArray.forEach(function(element) {
    element.addEventListener("change", function() {
      var funcName = this.id.split("-")[0];
      hideNodesWithText(funcName);
    });
  });
}

function hideDropdown(dropdownId) {
  var stdCDropdown = document.getElementById(dropdownId);
  if(stdCDropdown.classList.contains("show")) {
    stdCDropdown.classList.remove("show");
  }
}

function hideNodesWithText(text) {
  console.log("changing nodes with text ", text)
  $(".coverage-line-inner").each(function( index ) {
    var funcName = $( this ).find(".language-clike").text().trim()
    if(funcName===text) {
      $(this).toggleClass("hidden");
    }
  });
}

function addExpandSymbols() {
  $(".coverage-line-inner").each(function( index ) {
    var numberOfSubNodes = $(this).closest(".coverage-line").find(".coverage-line-inner").length
    if(numberOfSubNodes>1) {
      $(this).addClass("collapse-symbol");
    }
  });
}

function createFontSizeDropdown() {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn2");
  btn.id = "font-size-dropdown-btn";
  btn.innerHTML = `<div class="dropdown ">
    <button onclick="displayFontSizeDropdown()" id="font-size-dropdown-btn2" class="dropbtn font-size-dropdown">Fontsize</button>
    <div id="fontSizeDropdown" class="dropdown-content fontsize">
      <div>
        <div style="display:block" class="fontsize-option" data-fontsize="10px">10</div>
        <div style="display:block" class="fontsize-option" data-fontsize="11px">11</div>
        <div style="display:block" class="fontsize-option" data-fontsize="12px">12</div>
        <div style="display:block" class="fontsize-option" data-fontsize="13px">13</div>
        <div style="display:block" class="fontsize-option active" data-fontsize="14px">14</div>
        <div style="display:block" class="fontsize-option" data-fontsize="15px">15</div>
        <div style="display:block" class="fontsize-option" data-fontsize="16px">16</div>
      </div>
    </div>
  </div>`;
  return btn
}

function tabLineHover() {
  $(".coverage-line-inner").on({
    mouseenter: function () {
      var parent = $(this).closest(".coverage-line");
      if(parent===null) {
        return;
      } else {
        $(parent).addClass("hovered");
      }
    },
    mouseleave: function () {
      var parent = $(this).closest(".coverage-line");
      if(parent===null) {
        return;
      } else {
        $(parent).removeClass("hovered");
      }
    }
  });
}
