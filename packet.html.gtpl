<!DOCTYPE html>
<html>
<head>
  <title>Packet Diagram</title>
  <style>
    .packet {
      display: flex;
      flex-direction: row;
      margin: 10px;
      padding: 10px;
      align-items: stretch;
    }
    .field {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      align-items: stretch;
      border: 2px solid #000;
    }
    .field-item {
      margin: 3px;
      padding: 3px;
      /*width: 5em;*/
    }
    .toggle:checked ~ .field {
      display: none;
    }
    
    .field-name {
      height: 4em;
    }

    .field-value {
      word-wrap: break-word;
    }

  </style>
</head>
<body>
  <div class="packet">
    
    {{ range $name, $layerval := . }}

      
      {{- range $field, $contents := $layerval }}
        {{ if eq (typeof $contents) "string" }}
        <div class="field" id="{{ $field }}" draggable="true">
          <span class="field-item field-name">{{ fieldchange $field }}</span>
          <span class="field-item field-value">{{ $contents }}</span>
          <span class="field-item field-size">{{ sizeof $contents }} bytes</span>
          <button class="deletebutton" onclick="document.getElementById('{{ $field }}').style.display = 'none';">Delete</button> 
          <button class="up deletebutton">Left</button>
          <button class="down deletebutton">Right</button>
        </div>
        {{ end }}
      {{- end }}
    {{ end }}
  </div>
  <input type="button" class="deletebutton"
   onclick="const elements = document.getElementsByClassName('deletebutton');for (let i = 0; i < elements.length; i++) {elements[i].style.display = 'none';}" /> 

   <script>
    const container = document.querySelector('.packet');
const items = container.querySelectorAll('.field');

items.forEach(item => {
  item.addEventListener('dragstart', handleDragStart);
  item.addEventListener('dragover', handleDragOver);
  item.addEventListener('drop', handleDrop);

  const upBtn = item.querySelector('.up');
  const downBtn = item.querySelector('.down');

  upBtn.addEventListener('click', () => moveItem(item, -1));
  downBtn.addEventListener('click', () => moveItem(item, 1));
});

let dragSource = null; 

function handleDragStart(e) {
  dragSource = this;
  e.dataTransfer.effectAllowed = 'move';
}

function handleDragOver(e) {
  e.preventDefault(); 
}

function handleDrop(e) {
  e.preventDefault();
  if (this !== dragSource) {
    container.insertBefore(dragSource, this.nextSibling); 
  }
}

function moveItem(item, direction) {
  const sibling = direction === 1 ? item.nextSibling : item.previousSibling;
  if (sibling) {
    container.insertBefore(item, direction === 1 ? sibling.nextSibling : sibling);
  }
}

   </script>
</body>
</html>