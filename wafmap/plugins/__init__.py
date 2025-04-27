import os
import yaml

def load_plugins(plugin_dir):
    plugins = []
    for root, _, files in os.walk(plugin_dir):
        for file in files:
            if file.endswith(".yaml"):
                plugin_path = os.path.join(root, file)
                with open(plugin_path, 'r') as f:
                    plugin_data = yaml.safe_load(f)
                    plugins.append(plugin_data)
    return plugins

def load_detection_plugins():
    detection_dir = os.path.join(os.path.dirname(__file__), 'detection')
    return load_plugins(detection_dir)

def load_attack_plugins():
    attacks_dir = os.path.join(os.path.dirname(__file__), 'attacks')
    return load_plugins(attacks_dir)
