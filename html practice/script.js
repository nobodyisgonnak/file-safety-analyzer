 /* =====================================================
   FILE SAFETY ANALYZER - JAVASCRIPT
===================================================== */


/* =====================================================
   PAGE NAVIGATION
===================================================== */

function showPage(pageName) {

    // Get all pages
    const pages = document.querySelectorAll(".page");

    // Hide every page
    pages.forEach(function(page) {
        page.classList.remove("active-page");
    });

    // Show selected page
    const selectedPage = document.getElementById(pageName);

    if (selectedPage) {
        selectedPage.classList.add("active-page");
    }

    // Move screen to top
    window.scrollTo(0, 0);
}



/* =====================================================
   FILE VARIABLES
===================================================== */

let selectedFile = null;


/* =====================================================
   GET HTML ELEMENTS
===================================================== */

const fileInput = document.getElementById("fileInput");

const dropArea = document.getElementById("dropArea");

const selectedFileBox = document.getElementById("selectedFile");

const fileName = document.getElementById("fileName");

const fileInfo = document.getElementById("fileInfo");

const analyzeButton = document.getElementById("analyzeButton");

const clearButton = document.getElementById("clearButton");

const removeFile = document.getElementById("removeFile");



/* =====================================================
   FILE INPUT
===================================================== */

fileInput.addEventListener("change", function() {

    if (fileInput.files.length > 0) {

        selectedFile = fileInput.files[0];

        displaySelectedFile(selectedFile);

    }

});



/* =====================================================
   DISPLAY SELECTED FILE
===================================================== */

function displaySelectedFile(file) {

    fileName.textContent = file.name;

    fileInfo.textContent =
        formatFileSize(file.size) +
        " • " +
        getFileExtension(file.name);


    selectedFileBox.classList.remove("hidden");

    analyzeButton.disabled = false;

}



/* =====================================================
   GET FILE EXTENSION
===================================================== */

function getFileExtension(name) {

    const parts = name.split(".");

    if (parts.length === 1) {
        return "FILE";
    }

    return parts.pop().toUpperCase();

}



/* =====================================================
   FORMAT FILE SIZE
===================================================== */

function formatFileSize(bytes) {

    if (bytes < 1024) {
        return bytes + " B";
    }


    if (bytes < 1024 * 1024) {
        return (bytes / 1024).toFixed(1) + " KB";
    }


    return (bytes / (1024 * 1024)).toFixed(1) + " MB";

}



/* =====================================================
   CLEAR FILE
===================================================== */

function clearFile() {

    selectedFile = null;

    fileInput.value = "";

    selectedFileBox.classList.add("hidden");

    analyzeButton.disabled = true;

}


clearButton.addEventListener("click", clearFile);


removeFile.addEventListener("click", clearFile);



/* =====================================================
   DRAG AND DROP
===================================================== */

dropArea.addEventListener("dragover", function(event) {

    event.preventDefault();

    dropArea.classList.add("drag-over");

});


dropArea.addEventListener("dragleave", function() {

    dropArea.classList.remove("drag-over");

});


dropArea.addEventListener("drop", function(event) {

    event.preventDefault();

    dropArea.classList.remove("drag-over");


    if (event.dataTransfer.files.length > 0) {

        selectedFile = event.dataTransfer.files[0];

        displaySelectedFile(selectedFile);

    }

});



/* =====================================================
   ANALYZE BUTTON
===================================================== */

analyzeButton.addEventListener("click", function() {

    if (!selectedFile) {
        return;
    }


    // Go to analyzing page
    showPage("analyzing");


    // Start the visual analysis process
    startAnalysis();

});



/* =====================================================
   ANALYSIS PROCESS
===================================================== */

function startAnalysis() {

    const steps = document.querySelectorAll(".analysis-step");

    let currentStep = 0;


    // Reset steps

    steps.forEach(function(step) {
        step.classList.remove("active");
    });


    // First step

    steps[0].classList.add("active");


    const interval = setInterval(function() {

        currentStep++;


        if (currentStep < steps.length) {

            steps[currentStep].classList.add("active");

        }


        if (currentStep >= steps.length) {

            clearInterval(interval);

            showResult();

        }

    }, 700);

}



/* =====================================================
   SHOW RESULT
===================================================== */

function showResult() {

    if (!selectedFile) {
        return;
    }


    /* File name */

    document.getElementById("resultFileName").textContent =
        selectedFile.name;


    /* File type */

    const extension =
        getFileExtension(selectedFile.name);

    document.getElementById("resultFileType").textContent =
        extension;


    /* File size */

    document.getElementById("resultFileSize").textContent =
        formatFileSize(selectedFile.size);


    /* Date */

    const now = new Date();

    document.getElementById("resultDate").textContent =
        now.toLocaleString();


    /* Generate demo hash */

    document.getElementById("hashValue").textContent =
        generateDemoHash(selectedFile);


    /* Show result page */

    showPage("result");


    /* Add file to history */

    addToHistory(selectedFile);

}



/* =====================================================
   DEMO HASH
===================================================== */

function generateDemoHash(file) {

    /*
       This is only a frontend placeholder.

       Later your friend's Flask backend will send
       the real SHA-256 hash.
    */

    let text =
        file.name +
        file.size +
        file.lastModified;


    let hash = "";


    for (let i = 0; i < 64; i++) {

        hash +=
            "0123456789abcdef"[
                (text.charCodeAt(i % text.length) + i) % 16
            ];

    }


    return hash;

}



/* =====================================================
   ADD FILE TO HISTORY
===================================================== */

function addToHistory(file) {

    const historyBody =
        document.getElementById("historyBody");


    const row =
        document.createElement("tr");


    const currentNumber =
        historyBody.rows.length + 1;


    const date =
        new Date().toLocaleString();


    const extension =
        getFileExtension(file.name);


    row.innerHTML = `

        <td>${currentNumber}</td>

        <td>
            <span class="history-file">
                📄 ${file.name}
            </span>
        </td>

        <td>
            ${extension}
        </td>

        <td>
            ${formatFileSize(file.size)}
        </td>

        <td>
            ${date}
        </td>

        <td>
            <span class="status safe">
                ● Safe
            </span>
        </td>

        <td>
            <button class="view-button">
                ▣ View
            </button>
        </td>

    `;


    historyBody.appendChild(row);

}



/* =====================================================
   HISTORY VIEW BUTTON
===================================================== */

document.addEventListener("click", function(event) {

    if (event.target.classList.contains("view-button")) {

        alert(
            "File details will be displayed here."
        );

    }

});
