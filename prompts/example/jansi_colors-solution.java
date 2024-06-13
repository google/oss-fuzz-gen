import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.fusesource.jansi.io.Colors;

//Target method: [org.fusesource.jansi.io.Colors].roundRgbColor(int,int,int,int)
public class Fuzz {
    public static void fuzzerInitialize() {
        // Initialization before fuzzing the target method
    }

    public static void fuzzerTearDown() {
        // Teardown after the target method is called
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            int red = data.consumeInt(0, 255);
            int green = data.consumeInt(0, 255);
            int blue = data.consumeInt(0, 255);
            int alpha = data.consumeInt(0, 255);

            Colors.roundRgbColor(red, green, blue, alpha);
        } catch (RuntimeException e) {
            // Handle exceptions if needed
            throw e;
        }
    }
}
