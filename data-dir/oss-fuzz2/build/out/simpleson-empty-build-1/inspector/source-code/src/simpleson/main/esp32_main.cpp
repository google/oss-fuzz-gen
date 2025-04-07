#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "json.h"


void print_info()
{
    esp_chip_info_t chip_info;
    uint32_t flash_size = 0;
    esp_chip_info(&chip_info);
    if(esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        printf("Get flash size failed");
    }

    json::jobject silicon_rev, flash, heap, result;
    result["chip"] = CONFIG_IDF_TARGET;
    result["cores"] = chip_info.cores;
    result["BT"].set_boolean((chip_info.features & CHIP_FEATURE_BT));
    result["BTE"].set_boolean((chip_info.features & CHIP_FEATURE_BLE));
    result["LR-WPAN"].set_boolean((chip_info.features & CHIP_FEATURE_IEEE802154));
    silicon_rev["major"] = chip_info.revision / 100;
    silicon_rev["minor"] = chip_info.revision % 100;
    result["silicon"] = silicon_rev;
    flash["size"] = flash_size / (1024 * 1024);
    flash["type"] = (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external";
    result["flash"] = flash;
    heap["free"] = esp_get_free_heap_size();
    heap["minimum"] = esp_get_minimum_free_heap_size();
    result["heap"] = heap;
    printf("%s\n", result.as_string().c_str());
}

extern "C" void app_main()
{
    print_info();
}