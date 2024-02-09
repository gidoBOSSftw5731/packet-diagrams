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
    }
    .toggle:checked ~ .field {
      display: none;
    }
    /*
    .field-name {
      width: 50%;
    }
    .field-value {
      width: 50%;
    }
     */
  </style>
</head>
<body>
  <div class="packet">
    
    {{ range $name, $layerval := . }}

      
      {{- range $field, $contents := $layerval }}
        {{ if eq (typeof $contents) "string" }}
        <div class="field" id="{{ $field }}">
          <span class="field-item field-name">{{ fieldchange $field }}</span>
          <span class="field-item field-value">{{ $contents }}</span>
          <span class="field-item field-size">{{ sizeof $contents }} bytes</span>
          <input type="button" class="deletebutton" onclick="document.getElementById('{{ $field }}').style.display = 'none';" /> 
        </div>
        {{ end }}
      {{- end }}
    {{ end }}
  </div>
  <input type="button" class="deletebutton"
   onclick="const elements = document.getElementsByClassName('deletebutton');for (let i = 0; i < elements.length; i++) {elements[i].style.display = 'none';}" /> 

</body>
</html>